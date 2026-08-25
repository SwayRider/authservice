# authservice

Authentication and authorization service for the **SwayRider** platform.  
Provides user management, JWT-based authentication, service-to-service authentication, email verification, and password management.

> ⚠️ **Security Boundary**  
> The authservice must **never** be directly exposed to the internet.  
> All external access (mobile/web) must go through the API gateway.

---

## Responsibilities & Guarantees

The authservice is the **single source of truth** for:
- User identity & credentials
- JWT issuance and validation
- Refresh token lifecycle
- Service-to-service authentication
- Account level & admin authorization

The following invariants are **non-negotiable**:
- Passwords are **never stored or logged** in plaintext
- Refresh tokens are **single-use** and stored **hashed**
- JWTs are **RS256-signed** with rotating keys; the private key is **AES-256-GCM-encrypted at rest**, keyed by `ENCRYPTION_MASTER_KEY`
- JWT verification must work across key rotation
- All protected endpoints are guarded by interceptors

**Refresh-token IP binding is a soft anomaly signal, not a gate.** The client IP is resolved once by the API gateway (which never trusts client-supplied `X-Forwarded-For`), forwarded to this service as `x-orig-ip` gRPC metadata, and stored on the refresh token at login. At refresh the stored IP is compared against the forwarded IP and a mismatch is **logged but never blocks the refresh** — mobile clients legitimately change IP between requests. Client-supplied `X-Forwarded-For` is deliberately **not** honored (the service has no trusted reverse proxy of its own); tokens issued on direct/unauthenticated paths store no IP and never produce a mismatch.

---

## Architecture

The authservice exposes three server interfaces:

| Interface | Port | Purpose |
|---------|------|--------|
| REST / HTTP | 8080 | Public HTTP API via gRPC-gateway |
| gRPC | 8081 | Internal service-to-service communication |
| Web | 8000 | Static verification / reset pages |

### Token Delivery

Refresh tokens are delivered as **HTTP-only cookies** by the REST gateway (`CookieForwarder`).  
When the `remember-me` header is set to `"true"`, the cookie lifetime is extended.

### Dependencies

- **PostgreSQL**  
  User data, refresh tokens, JWT keys, verification flows
- **mailservice**  
  Delivery of verification and password reset emails

### Background Processes

| Routine | Interval | Purpose |
|------|----------|--------|
| JWT Key Checker | Hourly | Rotates JWT signing keys 3 days before expiration; uses a PostgreSQL advisory lock to prevent duplicate rotation across instances |
| DB Maintenance | Hourly | Removes expired refresh tokens, verification tokens, and password reset tokens; uses a PostgreSQL advisory lock to prevent concurrent cleanup across instances |

All background tasks are **idempotent** and safe to restart.

---

## API Endpoints

All methods are exposed over gRPC (port 8081) and REST/HTTP (port 8080) via grpc-gateway.  
Every endpoint must be explicitly registered with a security level in `internal/server/server.go`.

| Method | Security Level | Notes |
|--------|---------------|-------|
| `Register` | Public | |
| `Login` | Public | |
| `Logout` | Public | |
| `Refresh` | Public | |
| `PublicKeys` | Public | Returns all currently valid JWT verification keys |
| `RequestPasswordReset` | Public | |
| `ResetPassword` | Public | |
| `CheckPasswordStrength` | Public | |
| `CheckVerificationToken` | Public | |
| `VerifyEmail` | Public | |
| `GetToken` | Public | Service client credentials flow |
| `WhoAmI` | Unverified | Requires authentication; works before email verification |
| `ChangePassword` | Unverified | Requires authentication |
| `CreateVerificationToken` | Unverified | Denied for already-verified users |
| `SetupMFA` | Unverified | Start TOTP enrollment → secret + otpauth URL + QR PNG |
| `EnableMFA` | Unverified | Verify one code → enable → issue backup codes |
| `DisableMFA` | Unverified | Disable (requires password) |
| `GetMFAStatus` | Unverified | Is MFA enabled for the caller? |
| `GenerateBackupCodes` | Unverified | Regenerate backup codes (requires password, invalidates old set) |
| `VerifyMFA` | Public | Exchange pending-login challenge + TOTP/backup code for tokens |
| `ChangeAccountType` | Admin | |
| `CreateAdmin` | Admin | |
| `CreateServiceClient` | Admin | |
| `DeleteServiceClient` | Admin | |
| `ListServiceClients` | Admin | |
| `InviteUser` | Admin | Add email to invite list; sends invite email |
| `RevokeInvite` | Admin | Remove email from invite list |
| `ListInvites` | Admin | List pending invites (paginated) |
| `WhoIs` | Admin or ServiceClient | ServiceClient requires `user:read` scope |
| `Check` / `Ping` | Public | Health checks |

---

## Configuration

Configuration is provided via **environment variables** or **CLI flags**.  
Requires **Go 1.26.2** or later.

### Server Configuration

| Env | Flag | Default | Description |
|----|------|--------|-------------|
| `HTTP_PORT` | `-http-port` | 8080 | REST API port |
| `GRPC_PORT` | `-grpc-port` | 8081 | gRPC port |
| `WEB_PORT` | `-web-port` | 8000 | Static web server |
| `WEB_PATH_PREFIX` | `-web-path-prefix` | `/web` | Web URL prefix |

> **Note:** the API gateway exposes these pages under its own `/web` namespace and maps it onto `WEB_PATH_PREFIX` (`AUTHSERVICE_WEB_PATH_PREFIX` in the gateway, default `/web`). If you change this value, update the gateway's `AUTHSERVICE_WEB_PATH_PREFIX` (and `AUTHSERVICE_WEB_PORT` with `WEB_PORT`) to match.

### Database Configuration

| Env | Flag | Default | Description |
|----|------|--------|-------------|
| `DB_HOST` | `-db-host` | | Database host |
| `DB_PORT` | `-db-port` | | Database port |
| `DB_NAME` | `-db-name` | | Database name |
| `DB_USER` | `-db-user` | | Database user |
| `DB_PASSWORD` | `-db-password` | | **Required** |
| `DB_SSL_MODE` | `-db-ssl-mode` | `disable` | |

### Service Configuration

| Env | Flag | Default | Description |
|----|------|--------|------------|
| `ADMIN_EMAIL` | `-admin-email` | | Initial admin user |
| `ADMIN_PASSWORD` | `-admin-password` | | Initial admin password |
| `MAILSERVICE_HOST` | `-mailservice-host` | | Mail service host |
| `MAILSERVICE_PORT` | `-mailservice-port` | | Mail service port |
| `MAILER_ADDRESS` | `-mailer-address` | `swayrider@example.com` | Outgoing email sender |
| `REGISTRATION_MODE` | `-registration-mode` | `open` | Registration mode: `open` or `invite_only` |
| `REGISTRATION_URL` | `-registration-url` | | Registration page URL — included in invite emails; required when `REGISTRATION_MODE=invite_only` |
| `VERIFICATION_URL` | `-verification-url` | | Default URL for email verification (used when caller omits `verificationUrl`) |
| `RESET_PASSWORD_URL` | `-reset-password-url` | | Default URL for password reset (used when caller omits `resetUrl`) |
| `MFA_RESET_URL` | `-mfa-reset-url` | | Default URL for MFA reset (used when caller omits `mfaResetUrl`) |
| `LOGIN_LOCKOUT_THRESHOLD` | `-login-lockout-threshold` | `5` | Failed logins before an account is locked out |
| `LOGIN_LOCKOUT_WINDOW_SECS` | `-login-lockout-window-secs` | `900` | Window over which failed logins are counted |
| `LOGIN_LOCKOUT_DURATION_SECS` | `-login-lockout-duration-secs` | `900` | How long an account stays locked out |
| `CLIENT_LOCKOUT_THRESHOLD` | `-client-lockout-threshold` | `5` | Failed attempts before a service client is locked out |
| `CLIENT_LOCKOUT_WINDOW_SECS` | `-client-lockout-window-secs` | `900` | Window over which failed client attempts are counted |
| `CLIENT_LOCKOUT_DURATION_SECS` | `-client-lockout-duration-secs` | `900` | How long a service client stays locked out |
| `EMAIL_COOLDOWN_SECS` | `-email-cooldown-secs` | `60` | Minimum time between verification/reset emails to the same address |
| `EMAIL_IP_MAX_ATTEMPTS` | `-email-ip-max-attempts` | `20` | Max verification/reset email requests per source IP |
| `EMAIL_IP_WINDOW_SECS` | `-email-ip-window-secs` | `900` | Window over which per-IP email requests are counted |
| `EMAIL_IP_LOCKOUT_DURATION_SECS` | `-email-ip-lockout-duration-secs` | `900` | Lockout duration after per-IP email limit is exceeded |
| `HEALTH_PROBE_TTL_SECS` | `-health-probe-ttl-secs` | `15` | How long a health probe result is cached |
| `RATE_LIMIT_RPS` | `-rate-limit-rps` | `50` | Requests per second allowed per source IP |
| `RATE_LIMIT_BURST` | `-rate-limit-burst` | `100` | Burst allowance per source IP |
| `RATE_LIMIT_IDLE_TTL_SECS` | `-rate-limit-idle-ttl-secs` | `300` | How long an idle per-IP rate limiter entry is kept |
| `COOKIE_NAMESPACE` | (env only) | | Overrides the cookie namespace prefix; unset uses the default namespace |
| `COOKIE_SAMESITE` | (env only) | `strict` | SameSite policy for the refresh-token cookie; valid values `strict`/`lax`, `none` is unsupported |
| `ENCRYPTION_MASTER_KEY` | `-encryption-master-key` | | **Required.** Base64-encoded 256-bit key encrypting the JWT signing private key at rest; generate with `openssl rand -base64 32`. Service refuses to start if unset/invalid |
| `ENCRYPTION_MASTER_KEY_PREVIOUS` | `-encryption-master-key-previous` | | Comma-separated retired master keys, used only to decrypt `jwt_keys` rows encrypted before a rotation |
| `JWT_KEY_RETENTION_DAYS` | `-jwt-key-retention-days` | `7` | Days an expired `jwt_keys` row is kept before the hourly maintenance routine deletes it |
| `HIBP_ENABLED` | `-hibp-enabled` | `true` | Reject passwords that appeared in a known data breach (Pwned Passwords API) |
| `HIBP_TIMEOUT_MS` | `-hibp-timeout-ms` | `3000` | Timeout for Pwned Passwords API requests |
| `HIBP_MIN_COUNT` | `-hibp-min-count` | `1` | Minimum breach occurrences before a password is rejected |
| `PASSWORD_HISTORY_SIZE` | `-password-history-size` | `5` | Recent password hashes kept per user; change/reset reject reusing one |
| `MFA_ENABLED` | `-mfa-enabled` | `true` | Global TOTP MFA switch; when `false` login skips the MFA step and MFA management endpoints fail closed |
| `MFA_CODE_LENGTH` | `-mfa-code-length` | `6` | TOTP digits (clamped to 1–8) |
| `MFA_TIME_STEP` | `-mfa-time-step-secs` | `30` | Seconds per TOTP time-step window |
| `MFA_GRACE_PERIOD` | `-mfa-grace-period` | `1` | Accept a code from this many windows before/after the current one (clock skew tolerance) |
| `MFA_BACKUP_CODES` | `-mfa-backup-codes` | `10` | Number of single-use backup codes issued on MFA setup |
| `MFA_CHALLENGE_TTL_SECS` | `-mfa-challenge-ttl-secs` | `300` | Lifetime of a pending-login MFA challenge token |
| `MFA_CHALLENGE_MAX_ATTEMPTS` | `-mfa-challenge-max-attempts` | `5` | TOTP/backup-code guesses allowed per challenge before it is invalidated |
| `MFA_LOCKOUT_THRESHOLD` | `-mfa-lockout-threshold` | `5` | Failed MFA verifications before the user's MFA throttle scope locks |
| `MFA_LOCKOUT_WINDOW_SECS` | `-mfa-lockout-window-secs` | `900` | Sliding window over which failed MFA verifications are counted |
| `MFA_LOCKOUT_DURATION_SECS` | `-mfa-lockout-duration-secs` | `900` | How long the MFA throttle scope stays locked |

---

## Multi-Factor Authentication (TOTP)

Per-user, opt-in TOTP second factor (RFC 6238, any standard authenticator app) with single-use backup codes and DB-backed pending-login challenge tokens. The `MFA_*` env vars above tune it; `MFA_ENABLED=false` is the global kill switch — login skips the MFA step entirely and every MFA management endpoint fails closed with `FailedPrecondition` (`mfa is disabled`).

### Enrollment flow

1. **`SetupMFA`** — generates a fresh base32 secret (shown once; the app also displays it grouped for manual entry), stores it **encrypted at rest** (AES-256-GCM via `ENCRYPTION_MASTER_KEY`, same KeyRing as the JWT private key), and returns it together with the `otpauth://` URL and a server-rendered QR PNG (`qr_png_base64`) for second-device enrollment. Re-running replaces the pending secret.
2. **`EnableMFA`** — the user proves control of the secret by presenting a valid TOTP code; MFA is then enabled and **10 × 8-char Crockford base32 backup codes** are issued (shown exactly once, only Argon2id hashes stored).
3. **`DisableMFA`** — requires the account password; deletes the enrollment row and all backup codes. **`GenerateBackupCodes`** — requires the password; replaces the old set (invalidating it) and returns the new codes once.
4. **`GetMFAStatus`** — reports whether the caller has MFA enabled.

### Login flow

When an account with MFA enabled logs in with a correct password, `Login` does **not** issue tokens. Instead it returns `mfa_required: true` plus a short-lived (`MFA_CHALLENGE_TTL_SECS`) single-use **challenge token** (256-bit random value; only its SHA-256 hash is stored). The client then calls **`VerifyMFA`** with the challenge token and either:

- a **TOTP code**, or
- a **backup code** (case/separator-insensitive; consumed atomically so a code can never be reused).

On success the challenge is consumed and the normal token pair is issued exactly like a completed login (refresh token stored, `remember-me` honored, cookie set via `CookieForwarder`). The response shape is identical for MFA and non-MFA accounts (clients branch on `mfa_required`), so the gate is not an account-enumeration signal. `Refresh` is unchanged: a refresh token is only ever issued after a completed MFA login.

### Brute-force defenses

- Each challenge allows `MFA_CHALLENGE_MAX_ATTEMPTS` guesses before it is invalidated.
- Failed verifications also count against a per-user **`mfa` throttle scope** in `security_throttle` (`MFA_LOCKOUT_*`), so an attacker who can loop successful password logins still cannot guess TOTP codes without bound.
- Backup codes are Argon2id-hashed at rest (salted, slow KDF — appropriate for their 40-bit entropy) and claimed with an atomic `UPDATE … WHERE used = false`, so replay is impossible.

### Endpoint error prefixes (contract with the gateway)

| Prefix | Meaning |
|--------|---------|
| `mfa is disabled` | Global switch off (`MFA_ENABLED=false`) |
| `mfa is already enabled` | EnableMFA/SetupMFA on an enabled account |
| `mfa is not set up` | Enable/GenerateBackupCodes without an enrollment row |
| `invalid authentication code` | TOTP/backup-code rejection in VerifyMFA |

---

## Password Breach Detection (HIBP)

`Register`, `ChangePassword` and `ResetPassword` (both the gRPC/REST surface and the web forms) reject passwords that have appeared in a known data breach. Checks run against the free [Pwned Passwords API](https://haveibeenpwned.com/Passwords) via the `swlib/hibp` client, which uses the **k-anonymity range protocol**: only the first 5 characters of the uppercase SHA-1 hash of the password are sent to the API, so the password itself (and its full hash) never leave the server. The `Add-Padding: true` header is sent so response size does not reveal whether a suffix matched.

Behavior:

- Rejection returns `InvalidArgument` with the stable message prefix `password has appeared in a known data breach`; the API gateway maps this to HTTP 400 with `reason: breached_password`, which the mobile client surfaces as a dedicated message.
- The check **fails open**: any HIBP error (timeout, rate limit, non-200) is logged and the password is accepted, so an HIBP outage never blocks users.
- The check runs after the cheap local validations (entropy, old password, reset token) and before hashing, and only when the password is not already rejected as too weak.
- `HIBP_ENABLED=false` disables the feature entirely (no network calls).

---

## Password History (Reuse Prevention)

`ChangePassword` and `ResetPassword` reject a new password that matches any of the user's **last `PASSWORD_HISTORY_SIZE` passwords** (default 5). Hashes are stored in the `password_history` table in the same Argon2id format as `users.password_hash`.

Behavior:

- Every newly-set password is recorded: registration seeds the history (including the bootstrapped admin's initial password), and change/reset append the new hash after it is stored.
- Because the current password is always the newest history entry, `ResetPassword` also catches a reset to the *current* password (it has no separate "must differ from old" check).
- Rejection returns `InvalidArgument` with the stable message prefix `password has been used before`; the API gateway maps this to HTTP 400 with `reason: password_reused`, which the mobile client surfaces as a dedicated message.
- History writes and the reuse check **fail open**: a DB error is logged and the password is accepted, so a history outage never blocks users.
- The hourly DB maintenance routine trims any per-user history beyond the configured size (safety net for rows written before the size was lowered).

---

## Database Schema (Overview)

| Table | Purpose | Notable Columns |
|-----|--------|----------------|
| `users` | User accounts & metadata | `account_level` (default `free`), `is_verified`, `is_admin`, `provider`, `provider_id` |
| `jwt_keys` | RSA signing keys (rotated) | `valid_until`, `private_key` (AES-256-GCM-encrypted when `private_key_encrypted`), `public_key`, `encryption_key_id` |
| `refresh_tokens` | Single-use refresh tokens | `revoked`, `valid_until`, `jwtid`, `created_ip`, `user_agent` |
| `verification_tokens` | Email verification | `token`, `valid_until` |
| `reset_password_tokens` | Password reset | `token`, `valid_until` |
| `service_clients` | Service credentials | `client_id`, `client_secret`, `scopes` (TEXT[]) |
| `registration_invites` | Pre-approved emails for invite-only mode | `email` (unique), `created_at` |
| `user_mfa` | TOTP MFA enrollment (one row per user) | `enabled`, `secret` (AES-256-GCM blob), `secret_key_id` |
| `mfa_backup_codes` | Single-use backup codes (Argon2id-hashed) | `code_hash`, `used`, `used_at` |
| `mfa_challenges` | Pending-login MFA challenge tokens (SHA-256-hashed) | `token_hash`, `attempts`, `valid_until` |

Service clients authenticate via the `GetToken` endpoint and are granted fine-grained access using the `scopes` array (e.g. `user:read`).

### Migrations

```bash
cd authservice
make migrate-up
make migrate-status
```

---

## Registration Modes

The `REGISTRATION_MODE` environment variable controls who can create new accounts.

### `open` (default)

Anyone can call `Register` and create an account. No restrictions.

### `invite_only`

An admin must pre-approve each email address before the owner can register.

**Flow:**

1. Admin calls `InviteUser` (via swctl or the admin API endpoint). The service creates an invite record and immediately sends an invitation email to that address containing the registration page URL (`REGISTRATION_URL`).
2. The invitee navigates to the registration page and calls `Register` with their email and a chosen password.
3. The service checks that the email has a pending invite. If not, it returns `PermissionDenied`.
4. On successful registration the invite is consumed (deleted), so each invite can only be used once.

**Managing invites via swctl:**

```bash
# Add an invite
swctl auth invite-user --auth-host … --user admin@… --password … user@example.com

# Remove an invite
swctl auth revoke-invite --auth-host … --user admin@… --password … user@example.com

# List pending invites
swctl auth list-invites --auth-host … --user admin@… --password …
```

**Notes:**

- The invite email is sent asynchronously; `InviteUser` returns immediately.
- If an email already has a pending invite, `InviteUser` returns `AlreadyExists`.
- Revoking a non-existent invite is a no-op (no error returned).
- The verification URL in registration emails is **not** affected by this setting — it is always provided by the calling client (mobile app / web app) in the `Register` request.
- `REGISTRATION_URL` is only used for invite emails. It can be left empty if `REGISTRATION_MODE=open`.

---

## Container Build

```bash
# Build and push container (from authservice/ directory)
make container-build
```

### Tagging

Tags are derived from the git state of the checkout:

| Branch / state | Tags applied |
|----------------|--------------|
| Version-tagged commit (`v1.2.3`) | `v1.2.3`, `latest` |
| `main` (untagged) | `v{last}-{date}-dev-b{N}`, `dev-latest` |
| Other branch | `v{last}-{branch}-b{N}` |
| Detached HEAD | `v{last}-{sha}-b{N}` |

Non-release builds get an incrementing build number (`-b{N}`) so repeated builds of the same branch don't overwrite each other. The number comes from querying the registry for the highest existing `-b{N}` tag on the same base tag and adding 1; the build fails if the registry can't be reached. Release builds are immutable and never get a build number.

### FORCE_DEV_LATEST

By default, a release build on a version-tagged commit (e.g., `v1.2.3`) pushes two tags: the version tag and `latest`. Set `FORCE_DEV_LATEST=1` to additionally push the `dev-latest` floating tag:

```bash
FORCE_DEV_LATEST=1 make container-build
```

Use this when a release should also advance environments that track `dev-latest`.
