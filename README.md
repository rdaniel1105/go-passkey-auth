# go-passkey-auth

A production-minded, standalone WebAuthn / Passkey authentication service in Go.

Backed by Redis (sessions, challenges) and PostgreSQL (users, credentials). Implements the full WebAuthn registration and authentication ceremony with deliberate spec decisions documented inline.

## Status

Early development. Scaffolding in progress.

## Planned stack

- Go 1.22+
- `go-chi/chi` — HTTP router
- `go-webauthn/webauthn` — WebAuthn ceremony
- `jackc/pgx` — Postgres driver
- `redis/go-redis` — Redis client
- `golang-migrate` — SQL migrations
- `joho/godotenv` — `.env` loading for local dev
- `testcontainers-go` — integration tests against real Postgres + Redis

## Quickstart

Coming soon.
