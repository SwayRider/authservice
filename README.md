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
- JWTs are **RS256-signed** with rotating keys
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

---

## Database Schema (Overview)

| Table | Purpose | Notable Columns |
|-----|--------|----------------|
| `users` | User accounts & metadata | `account_level` (default `free`), `is_verified`, `is_admin`, `provider`, `provider_id` |
| `jwt_keys` | RSA signing keys (rotated) | `valid_until`, `private_key`, `public_key` |
| `refresh_tokens` | Single-use refresh tokens | `revoked`, `valid_until`, `jwtid`, `created_ip`, `user_agent` |
| `verification_tokens` | Email verification | `token`, `valid_until` |
| `reset_password_tokens` | Password reset | `token`, `valid_until` |
| `service_clients` | Service credentials | `client_id`, `client_secret`, `scopes` (TEXT[]) |
| `registration_invites` | Pre-approved emails for invite-only mode | `email` (unique), `created_at` |

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
