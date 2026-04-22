# CLAUDE.md — authservice

Service-specific constraints for the SwayRider authentication service.
The root CLAUDE.md rules always apply.

## Scope

- Limit all work strictly to `backend/services/authservice/`
- Do NOT inspect other services unless explicitly instructed
- Do NOT inspect `swlib/` or `protos/` unless explicitly named

## Security Invariants (Never Violate)

- Passwords are hashed **only** via `swlib/crypto` (Argon2id)
- Never log passwords, password hashes, refresh tokens, or client secrets
- Refresh tokens are single-use and stored hashed
- JWTs are RS256-signed using keys from `jwt_keys`
- JWT key rotation logic must remain intact
- Public key verification must continue to work across key rotation

## API & Auth Rules

- gRPC endpoints and security levels are registered in `server/server.go`
- Any new endpoint **must** be explicitly registered with:
  - `PublicEndpoint`
  - `UnverifiedEndpoint`
  - `AdminEndpoint`
  - or `ServiceClientEndpoint`
- Do NOT bypass or weaken security interceptors

## Database Rules

- Database schema changes require a migration in `migrations/`
- Never modify existing migrations
- Token expiry semantics must not change silently
- Maintenance cleanup routines must remain idempotent

## Web Layer

- The web server (`internal/web/`) is for verification/reset flows only
- Do NOT expose authservice directly to the internet

## Execution Rules

- Follow plan → execute strictly
- No refactors outside the requested scope
- Assume all unspecified behavior is correct

## Documentation

Do NOT read documentation files by default.
Ask permission before reading:
- `README.md`
- architecture or API docs

