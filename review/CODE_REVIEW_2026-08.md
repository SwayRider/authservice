# Security Review — `authservice`

Date: 2026-08-16
Scope: `authservice` (server handlers, DB layer, models, migrations, web server) and its `swlib` dependencies (crypto, JWT, security, interceptors).
Method: static review only. **No code changes were made.**

---

## Summary

The service gets the fundamentals right: Argon2id password hashing with constant-time comparison, cryptographically secure token generation, RS256 JWT signing with automatic key rotation (advisory-lock guarded), centralized endpoint authorization profiles, HttpOnly/SameSite cookies, and uniform login-failure messages. That said, there are several concrete defects that break the service's own documented security invariants, the most serious being broken refresh-token rotation and plaintext refresh-token storage. The "single-use hashed refresh tokens" guarantee is currently not met.

---

## Critical

### 1. ~~Refresh-token rotation is broken — tokens are not single-use~~ — FIXED 2026-08-17
`internal/server/authentication.go`, `Refresh()`

**Fix:** `Refresh()` now deletes the resolved `refreshToken` (cookie-or-body) instead of `req.RefreshToken`, matching the pattern already used in `Logout()`. Regression test `TestRefresh_DeletesCookieSourcedToken` added in `internal/server/authentication_test.go`, verified to fail on the pre-fix code and pass after.

The handler resolves the token from *either* the cookie or the request body into the local variable `refreshToken`, but then deletes the *wrong* value:

```go
refreshToken, _ := security.GetRefreshToken(ctx)
if refreshToken == "" {
    refreshToken = req.RefreshToken
}
...
err = s.DB().DeleteRefreshToken(ctx, req.RefreshToken)  // ← uses req, not refreshToken
```

When the token arrives via cookie (the normal REST flow), `req.RefreshToken` is empty, so `DELETE WHERE token = ''` matches nothing and the old token survives. The same refresh token can therefore be replayed indefinitely — directly violating the documented **"single-use refresh tokens"** invariant and defeating the token-theft detection that IP/user-agent binding is meant to provide.

The unit tests only exercise the body-based path (`TestRefresh_*` pass `RefreshToken` in the request), so this is invisible to the test suite.

### 2. ~~Refresh tokens are stored in **plaintext**, contradicting the documented invariant~~ — FIXED 2026-08-17
`internal/db/refresh_tokens.go`, `migrations/0001_003_create_refresh_tokens_table.sql`

**Fix:** Refresh tokens are now hashed with unsalted SHA-256 (`model.HashToken`, `internal/model/refresh_token.go`) before persistence — plain SHA-256 is appropriate since the token already carries 256 bits of entropy from `GenerateSecureRandomString`, unlike a low-entropy password. `CreateRefreshToken`/`GetRefreshToken`/`DeleteRefreshToken` in `internal/db/refresh_tokens.go` now hash-and-lookup rather than storing/matching plaintext. Migration `0001_010_hash_refresh_tokens.sql` renames the `token` column to `token_hash`. Note: this migration invalidates every live refresh token as a one-time, intentional effect of the fix (old plaintext rows can never match a hash-based lookup) — this should be called out in deploy/release notes. Unit tests for `HashToken` added in `internal/model/refresh_token_test.go`; no automated DB-integration test exists (none existed for this table before this fix either) — verify end-to-end via `make migrate-up` against a local Postgres plus a manual Login → Refresh → Logout pass.

Both the README and the repo-level docs state the invariant *"Refresh tokens are … stored hashed."* The implementation stores the raw token:

- `CreateRefreshToken` does `INSERT ... (token, ...) VALUES ($1, ...)` with `token.Token` (plaintext).
- `GetRefreshToken` looks up `WHERE token = $1` (plaintext equality).
- The column is `token TEXT NOT NULL` with a unique index on the raw value.

If the database is compromised, every live refresh token is directly usable for session hijacking. Verification tokens and password-reset tokens are also stored plaintext — more defensible for those (the email already carries them), but refresh tokens are explicitly *supposed* to be hashed per the project's own spec.

### 3. ~~The DB-maintenance routine never runs cleanup~~ — FIXED 2026-08-17
`cmd/authservice/main.go`, `dbMaintenance()`

**Fix:** `dbMaintenance()` now calls `dbconn.DoDatabaseMaintenance(ctx)` instead of `dbconn.EnsureKeys(ctx)`. `go vet`/`go test ./authservice/...` pass (72 tests, 6 packages); no dedicated regression test was added since the routine is a ticker-driven background loop with no seam for unit testing without a refactor, out of scope for this one-line fix.

`dbMaintenance` was copy-pasted from `keyChecker` and calls `dbconn.EnsureKeys(...)` (key rotation) instead of `dbconn.DoDatabaseMaintenance(...)`:

```go
case <-ticker.C:
    if err := dbconn.EnsureKeys(ctx); err != nil {   // ← should be DoDatabaseMaintenance
        lg.Errorf("failed to ensure keys: %v", err)
    }
```

Effect: expired refresh/verification/reset tokens are **never purged**. They're still rejected by the `valid_until` checks at use time, but the tables grow unbounded and the dedicated maintenance path (`db/maintenance.go`, which *does* implement the cleanup with advisory locking) is dead code.

---

## High

### 4. ~~Password change/reset does **not** revoke active refresh tokens~~ — FIXED 2026-08-17
`internal/server/change_password.go`, `internal/server/password_reset.go`

**Fix:** Both `ChangePassword` and `ResetPassword` now call the new `DeleteRefreshTokensByUserID` (see #5's fix) immediately after `UpdatePassword` succeeds, revoking every active refresh token for the user. Failure to revoke is logged (`lg.Warnf`) but does not fail the response, matching the existing non-fatal-cleanup precedent already used for `DeleteResetPasswordToken` in `ResetPassword`. Regression tests `TestChangePassword_RevokesRefreshTokensOnSuccess`/`TestChangePassword_DoesNotRevokeOnWrongOldPassword` (`internal/server/change_password_test.go`) and `TestResetPassword_RevokesRefreshTokensOnSuccess`/`TestResetPassword_DoesNotRevokeOnInvalidToken` (`internal/server/password_reset_test.go`) added.

Both `ChangePassword` and `ResetPassword` update the password hash only. Neither revokes the user's existing refresh token(s). Consequence: a stolen refresh token (valid up to 30 days) keeps working after the user rotates their password — one of the standard reasons to rotate tokens.

### 5. ~~`CreateRefreshToken` invalidates the wrong column — old sessions are never revoked on login~~ — FIXED 2026-08-17
`internal/db/refresh_tokens.go`

**Fix:** Added `DeleteRefreshTokensByUserID(ctx, userID string) error` (`DELETE FROM refresh_tokens WHERE user_id = $1`, using the existing `idx_refresh_tokens_user_id` index — no migration needed). `CreateRefreshToken` now calls it instead of the mismatched `DeleteRefreshToken(ctx, user.ID)`. This mirrors the existing `DeleteVerificationToken`/`DeleteResetPasswordToken` by-user-id pattern in the same package. No dedicated DB-layer regression test was added: like the other methods in this file, it requires a real Postgres connection with no `sqlmock` seam in this codebase — verify manually via `make migrate-up` plus two logins as the same user, confirming only one row remains in `refresh_tokens` for that `user_id`.

```go
// intended: invalidate any existing token for this user
err = d.DeleteRefreshToken(ctx, user.ID)
```

`DeleteRefreshToken` runs `DELETE FROM refresh_tokens WHERE token = $1`, but `user.ID` is a UUID, not a token. This never matches. The documented behavior ("only one refresh token per user; creating a new token invalidates existing ones") is not implemented, so multiple concurrent sessions accumulate. (The schema has no unique constraint on `user_id`, so nothing else enforces it either.)

### 6. ~~Nil-pointer dereference (crash/DoS) on DB connection errors in `Login` and `GetToken`~~ — FIXED 2026-08-17
`internal/server/authentication.go`

**Fix:** Both `Login` and `GetToken` now return `codes.Internal, "internal error"` immediately when `GetUserByEmail`/`GetServiceClientByID` returns a non-sentinel error, instead of falling through to dereference a nil `u`/`clnt`. Regression tests `TestLogin_DBConnectionError` and `TestGetToken_DBConnectionError` added in `internal/server/authentication_test.go`, verified to panic on the pre-fix code and pass after (confirmed by temporarily reverting the source fix and re-running).

Both handlers follow this pattern:

```go
u, err := s.DB().GetUserByEmail(ctx, req.Email)
if err != nil {
    if errors.Is(err, db.ErrUserNotFound) {
        return nil, status.Error(...)
    }
    // non-ErrUserNotFound error: falls through
}
if !u.PasswordHash.Valid { ... }   // u is nil → panic
```

`GetUserByEmail`/`GetServiceClientByID` return non-sentinel errors (e.g. from `checkConnection()`). On a DB outage, an unauthenticated caller can trigger a nil-pointer panic in the auth path — a denial-of-service vector that also turns an outage into a crash. `GetToken` has the identical bug with `clnt.ClientSecretHash`.

### 7. No brute-force protection on credential endpoints
No rate limiting, throttling, or account lockout anywhere in the service. `Login`, `Register`, `GetToken`, `RequestPasswordReset`, `ResetPassword`, and `CheckVerificationToken` are all `PublicEndpoint`s with no attempt tracking. (The README notes the authservice sits behind a gateway, so the gateway *may* rate-limit — but the gRPC port 8081 and any direct-to-service path are unprotected, and the login handler itself has no defense-in-depth.)

---

## Medium

### 8. ~~Refresh rotation is not atomic (TOCTOU)~~ — FIXED 2026-08-17
`internal/db/refresh_tokens.go`, `internal/server/authentication.go` `Refresh()`

**Fix:** `GetRefreshToken` + `DeleteRefreshToken` are replaced by a single `ConsumeRefreshToken` (`internal/db/refresh_tokens.go`) using `DELETE FROM refresh_tokens WHERE token_hash = $1 RETURNING ...`, atomic at the Postgres row-lock level — under concurrent requests for the same token, exactly one caller gets the row back, the other gets zero rows → `ErrNoRefreshTokenFound` → `Unauthenticated`. Mirrors the existing `INSERT ... RETURNING` idiom already in `internal/db/throttle.go`; no new transaction machinery introduced. `Refresh()` (`internal/server/authentication.go`) now hard-fails on a not-found/already-consumed token instead of the old delete-error-swallowed-and-proceeds path. While rewriting the row scan, also fixed a latent bug where the `revoked` column was never scanned back, meaning `RefreshToken.Verify()`'s revoked check was previously dead code. Regression tests updated/added in `internal/server/authentication_test.go` (`TestRefresh_DeletesCookieSourcedToken` adapted to the single-call seam; new `TestRefresh_AlreadyConsumedTokenFailsWithoutIssuingNewTokens` asserts `CreateRefreshToken` is never reached when consumption fails). `go build`/`go vet`/`go test ./authservice/...` pass (105 tests, 6 packages). No new migration needed — `refresh_tokens` already has `token_hash` and `revoked`. Not yet verified against a real concurrent-request race on Postgres (no DB-integration tests exist for this table, consistent with #2/#5); recommend a manual two-concurrent-refresh check via `make migrate-up` before relying on this in production.

Even if issue #1 were fixed, the `GetRefreshToken` → `DeleteRefreshToken` → `createAuthTokens` sequence is three separate statements. Two concurrent refreshes with the same token can both read it before either deletes, each getting a fresh pair. A transactional read-and-delete (e.g. `DELETE … RETURNING`) would enforce true single-use.

### 9. ~~IP binding is fragile and can break refresh behind multi-hop proxies~~ — FIXED 2026-08-17
`internal/model/refresh_token.go` `Verify()`, `swlib/grpc/interceptors/clientinfointerceptor.go`

**Fix:** The IP binding is now a **soft anomaly signal, never a gate**, and the plumbing is fixed end to end. `ClientInfoInterceptor` reads the client IP only from the gateway-forwarded `x-orig-ip` metadata — client-supplied `x-forwarded-for` is never honored (the service has no trusted reverse proxy of its own) — and normalizes it to a single IP. `swayrider-api` forwards its peer-gated resolved IP (see swayrider-api review #2) as `x-orig-ip` on `Login`/`Refresh` via a variadic `ClientInfo` argument in `grpcclients/authclient`. `RefreshToken.Verify` no longer checks the IP; new `MatchesIP` parses the comma-separated chain robustly and `Refresh` logs a warning on mismatch but always proceeds — mobile clients legitimately change IP between login and refresh. `NewRefreshToken`/`Login` store a normalized single IP. Tests added in `swlib/grpc/interceptors/clientinfointerceptor_test.go`, `authservice/internal/model/refresh_token_test.go`, and `authservice/internal/server/authentication_test.go`; docs updated in both READMEs.

The model test (`refresh_token_test.go`) documents the *intended* behavior: store a **single** client IP, then match it anywhere in the X-Forwarded-For chain. But `ClientInfoInterceptor` stores `value[0]` — the **entire raw header value** — as `t.Ip` at login. When XFF contains more than one IP (the common proxy case), the stored value is a comma-joined string, and `slices.Contains(split(origIp), t.Ip)` never matches the full chain, so refresh verification spuriously fails. Conversely, mobile clients whose IP changes between login and refresh will also be rejected. This is a correctness/UX issue that can masquerade as (or be worked around by) disabling the binding.

### 10. ~~Email/user enumeration~~ — FIXED 2026-08-17
`internal/server/registration.go`, `internal/server/invites.go`, `internal/server/authentication.go` `GetToken()`

**Fix:** Investigation found `IsEmailInvited` (`internal/db/invites.go:170`) already filters on `registered = false`, so an already-registered email in invite-only mode was already colliding with the never-invited case (`PermissionDenied`) — the real unauthenticated leaks were `Register`'s duplicate-email `AlreadyExists` and `GetToken`'s `NotFound`. `Register` now always returns the same generic response (empty `user_id`, generic message) whether the email is new, already registered, or (invite-only) not invited; on a genuine duplicate it asynchronously notifies the real owner by reusing the existing `sendPasswordResetEmail` helper (no new mail template, no cross-repo `mailservice` change) — mirrors the `VerifyEmail`/`RequestPasswordReset` pattern already in this file. `GetToken`'s unknown-`client_id` branch now returns the same `Unauthenticated "service client authentication error"` as the wrong-secret branch, mirroring `Login`'s existing uniform-message pattern. `InviteUser` (admin-only, `AdminEndpoint` per `server.go:78` — not an unauthenticated attacker surface, but fixed for defense-in-depth) collapses its two `AlreadyExists` messages (pending invite vs. already-registered) into one uniform message. New tests: `registration_test.go` (`TestRegister_DuplicateEmail_ReturnsGenericResponseAndNotifiesOwner`, `TestRegister_InviteOnly_NotInvited_ReturnsGenericResponseWithoutCreatingUser`, `TestRegister_InviteOnly_Invited_Succeeds`, plus the existing cooldown tests updated for the new empty-`user_id` response shape), new `invites_test.go` (`InviteUser` had zero prior coverage — added `TestInviteUser_PendingVsAlreadyRegistered_ReturnUniformMessage` plus baseline coverage), and `authentication_test.go`'s `TestGetToken_ClientNotFound` updated to assert the uniform message. `go build`/`go vet`/`go test ./authservice/...` pass (113 tests, 6 packages). Known residual limitation (same risk level accepted by the pre-existing `VerifyEmail`/`RequestPasswordReset` endpoints, not a regression): response *content* is now uniform across branches, but request *timing* isn't equalized (0 vs. 1 vs. 2 DB calls depending on branch) — out of scope for this fix.

- `Register` returns `AlreadyExists: "user with email X already exists"` — leaks account existence.
- In `invite_only` mode, `Register` distinguishes `PermissionDenied` ("invitation required") from `AlreadyExists` — leaks invite vs. account status.
- `InviteUser` returns `AlreadyExists: "user X already has an active account"`.
- `GetToken` returns `NotFound` for unknown client IDs but `Unauthenticated` for a wrong secret — leaks which `client_id`s exist.

`VerifyEmail` and `RequestPasswordReset` deliberately avoid enumeration (good), but the registration/invite paths undercut that.

### 11. ~~Refresh token value logged~~ — NOT REPRODUCED 2026-08-17
`internal/db/refresh_tokens.go` (now `ConsumeRefreshToken()`, previously `GetRefreshToken()`)

**Investigation:** Checked the not-found branch this item points at, in both the current code and the commit this branch started from (before any of the #8/#10 fixes touched this file): the line has always been `lg.Debugf("no refresh token found")`, with no `%s`/token argument. Grepped the whole `authservice` module for any log call that embeds a raw refresh token and found none. This finding doesn't reproduce against this codebase — leaving unfixed, no code change made.

`internal/db/refresh_tokens.go` `GetRefreshToken()`: `lg.Debugf("no refresh token found: %s", token)` logs the raw token. Even at debug level, logging live bearer credentials is a smell worth removing.

### 12. ~~Unauthenticated email-spam vector~~ — FIXED 2026-08-17
`internal/db/throttle.go`, `internal/server/throttle.go`, `internal/server/registration.go`, `internal/server/password_reset.go`, `cmd/authservice/main.go`

**Investigation:** A prior same-day fix for #7 (`authservice` commit `0132c4c`, `swlib` commit `3f0ea75`, both already on `main` before this item was picked up) had already added a 60s per-*target-address* cooldown and claimed in its commit message to close #12. That claim was too strong: the per-address cooldown only stops repeated hits on the *same* address — an attacker cycling through many distinct never-before-seen addresses passed every time, and the accompanying gRPC-level rate limiter is a blunt global safety valve (50rps/100burst, loopback-exempt), not an anti-spam control. The only real defense against "many distinct addresses from one attacker" lived in `swayrider-api` (a separate service/repo), invisible from `authservice` alone.

**Fix:** Added a per-*source-IP* budget on top of the existing per-address cooldown, reusing the same `RecordAttemptResult`/`IsAttemptLocked` counter-window-lockout machinery already backing the Login/GetToken lockouts (no new table/migration — `security_throttle`'s `(scope, identifier)` key already supports an IP-keyed scope). New scope `db.ScopeEmailSendByIP` is shared across `VerifyEmail`, `RequestPasswordReset`, and both of `Register`'s mail-sending branches, mirroring the existing anti-endpoint-hopping reasoning for `ScopeEmailVerification`. The check only ever gates the mail send (never the response shape or, for `Register`, account creation), preserving the #10 anti-enumeration invariant. New `ThrottleConfig` fields (`EmailIPMaxAttempts`/`EmailIPWindow`/`EmailIPLockoutDuration`, defaults 20/900s/900s) wired through `main.go` (`EMAIL_IP_MAX_ATTEMPTS`/`EMAIL_IP_WINDOW_SECS`/`EMAIL_IP_LOCKOUT_DURATION_SECS`) and both `infra/dev*/layer-20` compose/env files. New tests in `registration_test.go`/`password_reset_test.go` cover the IP-locked-skips-send and shared-scope-and-identifier cases for all three handlers. `go build`/`go vet`/`go test ./authservice/...` pass (119 tests, 6 packages). Residual limitation, consistent with the pre-existing Login/GetToken lockouts and the gRPC limiter: this is a per-source-IP bucket, so callers sharing one egress IP (corporate/carrier-grade NAT) share one budget.

`VerifyEmail` and `RequestPasswordReset` are public and send mail to *any* address, with no rate limiting (see #7). Combined, they can be abused to bombard arbitrary inboxes.

### 13. ~~Cookie `Secure` flag depends on forwarded proto~~ — FIXED 2026-08-17
`internal/server/authentication.go` `CookieHeaderMatcher()`

**Investigation:** Traced the mechanism end to end. `ClientInfoInterceptor` (`swlib/grpc/interceptors/clientinfointerceptor.go`) already correctly parses `x-forwarded-proto` gRPC metadata into `security.SecureKey`, and `CookieForwarder` already correctly reads that into the cookie's `Secure` flag via `cookies.NewCookieOptsFromContext`. The actual bug: grpc-gateway's `DefaultHeaderMatcher` doesn't forward `X-Forwarded-Proto` from the incoming HTTP request into gRPC metadata at all (not on its permanent-header allowlist), so the signal was silently dropped before the interceptor ever saw it — regardless of what actually terminated TLS. Considered and rejected a static per-deployment `COOKIE_SECURE` flag: authservice's own REST gateway (where `CookieForwarder` runs) is legitimately reachable both over plain HTTP (direct internal debugging) and potentially through something terminating TLS internally, sometimes within the same environment/instance, so a single static default can't distinguish the two per request the way the actual header can.

**Fix:** `CookieHeaderMatcher` (`internal/server/authentication.go`) already special-cased the `Cookie` header for exactly this kind of grpc-gateway default-matcher gap — extended it to also forward `X-Forwarded-Proto`, case-insensitively, alongside the existing `cookie` case. No changes needed to `ClientInfoInterceptor` or `CookieForwarder` — both were already correct once the header actually arrives. Trusting this header unconditionally once forwarded is consistent with the trust model already established for `x-orig-ip` in fix #9 (authservice's ports are only reachable by trusted internal callers). Net effect: a direct plain-HTTP debug request forwards no header → `Secure: false`, unchanged from today, debugging still works; a request arriving via something that terminates TLS and sets `X-Forwarded-Proto: https` now actually reaches the interceptor → `Secure: true`. New tests: `TestCookieHeaderMatcher` extended with `x-forwarded-proto` cases, new `TestCookieForwarder_SetsSecureFromContext`/`TestCookieForwarder_DefaultsInsecureWithoutSignal` (`CookieForwarder` had zero prior coverage). `go build`/`go vet`/`go test ./authservice/...` pass (124 tests, 6 packages). Not yet verified against a running instance via `curl -H "X-Forwarded-Proto: https"` — recommended before relying on this in production, consistent with other DB/network-dependent fixes in this review that weren't exercised against a live stack.

### 14. ~~Argon2id cost is below current OWASP guidance~~ — FIXED 2026-08-17
`swlib/crypto/hashing.go`

**Fix:** `argonTime` bumped `1 → 3` (`m=64MiB`, `p=4` unchanged), matching OWASP's recommended Argon2id profile (`m=65536, t=3, p=4`). This required touching `swlib` — the only Argon2id implementation in the monorepo, used by every hashing/verification call site in `authservice`.

Considered making the cost parameters configurable (env var) instead of a hardcoded bump — rejected: no existing precedent anywhere in the codebase for configurable crypto cost, no current use case for a different cost per environment, and it would add a way to accidentally weaken production hashing, which conflicts with treating authservice's security invariants as non-negotiable.

`VerifyPassword` already parses `m=`/`t=`/`p=` from the stored `$argon2id$...` string rather than trusting the current constants, so the format is self-describing and backwards compatible: this change only affects the cost of newly-created hashes (register, password reset, change password, admin creation, service-client secrets). Existing users' stored hashes keep verifying correctly at their original (weaker) cost until they next change or reset their password — confirmed by manually constructing a `t=1` hash and verifying it against `VerifyPassword` post-bump (verifies correctly, and still correctly rejects a wrong password).

New test: `TestCalculatePasswordHash_UsesCurrentCostParameters` in `swlib/crypto/crypto_test.go`, pinning the encoded cost string to `m=65536,t=3,p=4` so a future accidental regression back to a weaker cost fails a test rather than shipping silently. `go build`/`go vet`/`go test` pass for both `swlib` and `authservice` (570 tests, 25 packages). Committed on `swlib` branch `fix/argon2id-cost` — note this lands in a separate git repo from the `authservice`/`infra` branches for the rest of this review.

See also the new "opportunistic rehash-on-login" entry below — considered as part of this fix and explicitly deferred.

---

## Low / hardening notes

- **Opportunistic rehash-on-login** (deferred from #14): existing users' Argon2id hashes stay at whatever cost they were created with; there's no logic to transparently re-hash a user's password to current cost parameters on their next successful login. Legitimate hardening follow-up, but a larger change (touches the login path, needs a DB update call, new tests) than the Medium/awareness item warranted on its own. Still open.
- ~~**`VerifyPassword` can panic**~~ — FIXED 2026-08-17. `swlib/crypto/hashing.go`: `strings.Split` always returns ≥1 element, so `parts[1]` panicked on any input with zero `$` characters. Added a `len(parts) < 2` guard returning an error instead. New test `TestVerifyPassword_MalformedInput` (`""`, `"notahash"`). Committed on `swlib` branch `fix/crypto-hardening`.
- ~~**State-changing GET** on `/web/verify-user`~~ — FIXED 2026-08-17. Split the handler into a GET that renders a confirmation page (no DB access at all) whose inline script auto-submits a POST, and a POST that does the actual token validation/`MarkUserVerified`/`DeleteVerificationToken` — mirrors the pattern `reset_password.go` already used. Preserves the "click the email link, land on success" UX for real users while removing the CSRF-shaped/scanner-prefetchable GET. Also fixed a latent missing `return` after a `GetUserByID` error that could nil-pointer-deref on the following `IsVerified` check. First tests for the `internal/web` package (`verify_user_test.go`): GET renders correctly with a nil `dbConn` (proves it's side-effect-free) and preserves `u`/`t`; non-GET/POST methods get 405. The POST validation/mutation path isn't covered by automated tests (`dbConn` is a concrete `*db.DB` here, not the mockable interface `internal/server` uses) — recommend a manual check against a running instance before relying on this in production. Committed on `authservice` branch `fix/low-priority-hardening`.
- **Dead code**: `GetRememberMe`/`RememberMeKey` are unused in production handlers (only in tests); `remember-me` is set on `Login` but not on `Refresh`, so a refreshed session reverts to the 2-hour cookie TTL while the DB token remains valid 30 days. Still open.
- ~~**Cosmetic**: `jwtRotateThresshold` (typo)~~ — FIXED 2026-08-17, renamed to `jwtRotateThreshold` (purely internal Go constant, no config/env impact). "resigered", "eamil", "verificaiton", "RegstrationCompleteHandler" still open — not addressed in this pass.
- ~~**RSA 2048**~~ — FIXED 2026-08-17. Bumped `rsaKeySize` to 3072 in `swlib/crypto/keypair.go`. Keys rotate ~every 27 days (checked hourly), so the extra keygen cost is negligible. Updated the `TestCreateKeypair_PrivateKeyParseable` bit-length assertion to match. Committed on `swlib` branch `fix/crypto-hardening`.
- ~~**`ListInvites`/`ListServiceClients` pagination**~~ — FIXED 2026-08-17. `ListInvites` clamped negative `page`/`pageSize` to `0`, which the DB layer treats as "no LIMIT/OFFSET — return every row" (and would've produced a negative `OFFSET` for `page=0` with `pageSize>0` had that branch not short-circuited first). `ListServiceClients` already clamped to `page=1, pageSize=10`. Added shared `defaultPage`/`defaultPageSize` constants in `invites.go` and used them in both places. New test `TestListInvites_PaginationDefaults`, mirroring the existing `TestListServiceClients_PaginationDefaults`. Committed on `authservice` branch `fix/low-priority-hardening`.

---

## Positive observations

- Argon2id hashing with per-password random salt and `subtle.ConstantTimeCompare`.
- Secure random (256-bit) refresh/verification/reset tokens and 512-bit client secrets.
- RS256 key rotation 3 days pre-expiry, cross-instance coordinated via `pg_try_advisory_lock`, with multi-key verification for seamless rotation.
- Endpoint security profiles centralized in `server.go` `init()`; unknown endpoints default to *require auth* (`GetEndpointProfile` returns the zero profile).
- Uniform `"invalid email or password"` for both unknown-user and wrong-password cases.
- `VerifyEmail`/`RequestPasswordReset` send asynchronously and always return success (anti-enumeration).
- Service-client secrets hashed; scopes resolved as intersection with explicit `*` wildcard semantics.
- HttpOnly + SameSite=Lax refresh cookie.

---

## Test-coverage gaps

- No test for **cookie-based** refresh (the bug in #1).
- No test asserting the old refresh token is deleted/rotated (the `deleteRefreshTokenFn` mock is never asserted).
- No test that password change/reset revokes refresh tokens.
- No integration tests against a real Postgres schema (all DB tests are mocks); the `CreateRefreshToken`/`DeleteRefreshToken` column bug (#5) and plaintext storage (#2) would only surface there.

---

## Recommended fix order

1. **#1** — broken rotation → replayable refresh tokens.
2. **#2** — plaintext token storage, documented as hashed.
3. **#3** — maintenance never runs.
4. **#4/#5** — session revocation on password change and login.
