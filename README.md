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

### Dependencies

- **PostgreSQL**  
  User data, refresh tokens, JWT keys, verification flows
- **mailservice**  
  Delivery of verification and password reset emails

### Background Processes

| Routine | Interval | Purpose |
|------|----------|--------|
| JWT Key Checker | Hourly | Ensure keys exist and rotate safely |
| DB Maintenance | Hourly | Cleanup expired tokens & housekeeping |

All background tasks are **idempotent** and safe to restart.

---

## Configuration

Configuration is provided via **environment variables** or **CLI flags**.

### Server Configuration

| Env | Flag | Default | Description |
|----|------|--------|-------------|
| `HTTP_PORT` | `-http-port` | 8080 | REST API port |
| `GRPC_PORT` | `-grpc-port` | 8081 | gRPC port |
| `WEB_PORT` | `-web-port` | 8000 | Static web server |
| `WEB_PATH_PREFIX` | `-web-path-prefix` | `/web` | Web URL prefix |

### Database Configuration

| Env | Flag | Description |
|----|------|------------|
| `DB_HOST` | `-db-host` | Database host |
| `DB_PORT` | `-db-port` | Database port |
| `DB_NAME` | `-db-name` | Database name |
| `DB_USER` | `-db-user` | Database user |
| `DB_PASSWORD` | `-db-password` | **Required** |
| `DB_SSL_MODE` | `-db-ssl-mode` | `disable` |

### Service Configuration

| Env | Flag | Description |
|----|------|------------|
| `ADMIN_EMAIL` | `-admin-email` | Initial admin user |
| `ADMIN_PASSWORD` | `-admin-password` | Initial admin password |
| `MAILSERVICE_HOST` | `-mailservice-host` | Mail service host |
| `MAILSERVICE_PORT` | `-mailservice-port` | Mail service port |
| `MAILER_ADDRESS` | `-mailer-address` | Outgoing email sender |

---

## Database Schema (Overview)

| Table | Purpose |
|-----|--------|
| `users` | User accounts & metadata |
| `jwt_keys` | RSA signing keys (rotated) |
| `refresh_tokens` | Single-use refresh tokens |
| `verification_tokens` | Email verification |
| `reset_password_tokens` | Password reset |
| `service_clients` | Service credentials |

### Migrations

```bash
cd backend/services/authservice
make migrate-up
make migrate-status

