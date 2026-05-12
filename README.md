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

Service clients authenticate via the `GetToken` endpoint and are granted fine-grained access using the `scopes` array (e.g. `user:read`).

### Migrations

```bash
cd backend/services/authservice
make migrate-up
make migrate-status
```

---

## Container Build

```bash
# Build and push container (from authservice/ directory)
make container-build
```

### FORCE_DEV_LATEST

By default, a release build on a version-tagged commit (e.g., `v1.2.3`) pushes two tags: the version tag and `latest`. Set `FORCE_DEV_LATEST=1` to additionally push the `dev-latest` floating tag:

```bash
FORCE_DEV_LATEST=1 make container-build
```

Use this when a release should also advance environments that track `dev-latest`.
