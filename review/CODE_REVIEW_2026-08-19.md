# Code Review — 2026-08-19

Follow-up security audit of the full current codebase (not diff-based), cross-checked against [`review/CODE_REVIEW_2026-08.md`](CODE_REVIEW_2026-08.md) and [`Docs/AuthImprovement/INDEX.md`](../../Docs/AuthImprovement/INDEX.md). See [`Docs/REVIEW.md`](../../Docs/REVIEW.md) for how findings in this file are tracked.

**Verification of prior review:** all previously-FIXED items were re-verified against current code with no regressions — single-use atomic refresh-token consumption (`ConsumeRefreshToken`'s `DELETE ... RETURNING`), SHA-256 hashed refresh-token storage, `dbMaintenance` correctly wired to `DoDatabaseMaintenance` (`cmd/authservice/main.go:416`, not the old copy-paste bug reusing `EnsureKeys`), password-change/reset revoking refresh tokens via `DeleteRefreshTokensByUserID`, Argon2id at OWASP cost (`m=65536,t=3,p=4`), nil-deref guards in `Login`/`GetToken`, and uniform enumeration-safe responses. Login/GetToken/email-send brute-force protection is implemented (`internal/db/throttle.go`, Postgres-backed lockout), matching the hardening roadmap's "already implemented" note.

No SQL injection found (all queries parameterized; the one `fmt.Sprintf` in `internal/db/invites.go:194/210` only interpolates a `%t`-formatted `bool`, not attacker-controlled data). No IDOR found on `WhoIs`/`ChangeAccountType` — both correctly gated `Admin`/`ServiceClient(user:read)`. Algorithm-confusion is prevented (explicit RSA method-type assertion plus `WithValidMethods([RS256])`). Key rotation logic and the advisory-lock double-check-locking pattern in `internal/db/jwt_keys.go` are correct.

**Already tracked, not re-reported here:** JWT private keys stored unencrypted in `jwt_keys.private_key` — listed as pending in `Docs/AuthImprovement/AUTH_IMPROVEMENTS_PHASE_01.md`; opportunistic rehash-on-login and `remember-me` not honored on `Refresh` — already logged as open/deferred in the existing review's Low section; finding #11 (refresh token logged) — confirmed still not reproducible, no log call embeds a raw token.

### 1. `jwt.VerifyToken` silently discards the claims-parsing error

`swlib/jwt/jwt.go:196-197`:

```go
jwtClaims = &Claims{}
jwtClaims.FromMapClaims(mapClaims)
```

The return value of `FromMapClaims` (which validates required registered claims, `jti`, and dispatches/parses the `swayrider` sub-claims) is never checked. A validly-signed-but-malformed token (e.g. missing `jti`, malformed `swayrider` claim map) is returned as "verified" (`err == nil`) with a zero-value/partial `Claims` struct instead of being rejected outright. This is shared code — see [[swlib]] and [[swayrider-api]] reviews, both of which surfaced the same finding independently from their own call sites.

**Failure scenario:** not currently exploitable end-to-end — every observed caller (`swlib/security/endpoint_profile.go`'s `Evaluate` type switch on `claims.SwayRiderClaims`, and `swayrider-api/internal/middleware/auth.go`'s `RequireAdmin` type assertion) fails closed when `SwayRiderClaims` comes back `nil`. It's a latent defensive-coding gap: any future caller that trusts `err == nil` without re-checking claim types/values would be exposed, and it currently produces confusing "invalid jwt" errors instead of a clear parse error.

**Fix:** propagate the error — `if err = jwtClaims.FromMapClaims(mapClaims); err != nil { return }`. Severity: Low/Medium.

### 2. Non-constant-time comparison of verification/password-reset tokens

`internal/model/verification_token.go:53` and `internal/model/password_reset_token.go:52`:

```go
return t.UserId == userId && t.Token == token && t.IsNotExpired()
```

Both tokens are fetched from Postgres by `user_id` and then compared against the caller-supplied token using Go's `==`, which short-circuits on first mismatched byte — unlike refresh tokens (hashed DB lookup) and passwords (`subtle.ConstantTimeCompare` in `swlib/crypto/hashing.go:166`).

**Failure scenario:** an attacker who knows a target `user_id` (from the registration flow) could in theory use response-time variance across many `ResetPassword`/`CheckVerificationToken` calls to narrow down the 64-byte secure-random token. Practically low-risk: 512 bits of entropy plus network jitter make this infeasible today, and there's no per-guess lockout on these two endpoints specifically (only per-address/per-IP email-send cooldown, not guess-attempt throttling) — worth tightening for defense-in-depth consistency with the rest of the codebase.

**Fix:** `subtle.ConstantTimeCompare([]byte(t.Token), []byte(token)) == 1`. Severity: Low.

### 3. No attempt-lockout on `ResetPassword`/`CheckVerificationToken` token guessing

Unlike `Login`/`GetToken`, wrong-token attempts against `ResetPassword` and `CheckVerificationToken` aren't recorded in `security_throttle` — only the email-send path is rate-limited. Given 512-bit token entropy this is low practical risk, but it's an asymmetry worth noting alongside finding #2. Severity: Info.
