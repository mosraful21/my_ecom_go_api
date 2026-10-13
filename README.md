# My E-commerce Go API

## Local setup

1. Copy `.env.example` to `.env` and configure MySQL, Redis, and the SMS provider.
2. Create the database schema with `schema.sql`.
3. Set a strong `RECOVERY_SECRET` (at least 32 characters) and use `RECOVERY_COOKIE_SECURE=false` only for local HTTP development. Keep it `true` behind HTTPS in production.
4. Configure `BOOTSTRAP_ADMIN_NAME`, `BOOTSTRAP_ADMIN_PHONE`, and `BOOTSTRAP_ADMIN_PASSWORD` in your untracked `.env` file.
5. Run `go run ./cmd/bootstrap-admin` once to create the first administrator. The command refuses to create a bootstrap administrator if any admin row already exists. If you previously imported a schema containing the old demo admin row, this schema change does not remove it from an existing database; rotate that account's password or remove the demo row after confirming another administrator can log in.
6. Start the API with `go run .`.

Do not commit `.env`, bootstrap passwords, or recovery secrets. New administrator accounts should be created through the protected admin API after the first administrator exists.

## Checks

Run `go test ./...` and `go vet ./...`. GitHub Actions runs both on pushes to `main` and pull requests targeting `main`.

## Password policy

Passwords must be at least 8 bytes and no more than 72 bytes (bcrypt's input limit). Use a long, unique password.
