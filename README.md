# go-passkey-auth

A production-minded, standalone WebAuthn / Passkey authentication service in Go. Backed by Redis (sessions, challenges, guest tokens) and PostgreSQL (users, credentials). Implements the full WebAuthn registration and authentication ceremony with deliberate spec decisions documented inline.

The product is the API. A minimal HTML demo client is included so the flow can be exercised in a browser without writing any frontend code.

---

## What this is

- Full WebAuthn registration ceremony: opaque per-registration user handle, attestation verification, AAGUID/BE/BS persistence.
- Full authentication ceremony via discoverable credentials, including conditional-UI autofill on supported browsers.
- One-shot challenge consumption: a captured session id cannot be replayed even within its TTL.
- Strict sign-count validation with structured anomaly logging (counter reset, AAGUID mismatch, backup-flag flip).
- HttpOnly session cookies — the token is never returned in any JSON body.
- Guest → registered promotion as a first-class flow.
- Soft-delete credentials with a last-credential guard enforced in a transaction.

## Why passkeys

Passkeys are the consumer-facing form of WebAuthn discoverable credentials: an asymmetric key pair held by a platform authenticator (iCloud Keychain, Google Password Manager, 1Password, hardware key). Sign-in happens with a biometric or PIN, no password, no SMS. The spec is at [w3.org/TR/webauthn-3](https://www.w3.org/TR/webauthn-3/).

---

## Architecture

```
cmd/
  server/main.go               entrypoint, wires config -> stores -> handlers -> http.Server
internal/
  api/
    handler/                   http handlers
      auth.go                  /auth/* (register, login, logout, guest, promote)
      user.go                  /users/me + /users/me/credentials
      health.go                /health, /health/ready
      response.go              writeJSON + writeError (stable codes, no err leak)
      cookie.go                HttpOnly cookie helpers (session + guest)
    middleware/
      session.go               RequireSession: cookie -> session store -> ctx
      logger.go                structured slog per request
    static/index.html          single-page demo client
    router.go                  chi routes
  domain/                      User, Credential, sentinel errors
  webauthn/                    Service wrapping go-webauthn/webauthn
    options.go                 NewService + spec decisions
    user.go                    library User adapter + opaque handle generation
    attestation.go             both attestation axes (format + type) policy
    service.go                 Begin/Complete + ParseCredential* helpers
  store/
    postgres/                  pgx-backed user + credential stores
      migrations/              embedded golang-migrate SQL files
    redis/                     session, challenge, guest stores
  config/config.go             godotenv + os.Getenv + sentinel errors
  testutil/webauthntest/       software authenticator for integration tests
tests/integration/             end-to-end via testcontainers
```

---

## API reference

Base path: `/api/v1`.

All request and response bodies are JSON. Binary fields (challenge, credential id, raw id) are base64url-encoded strings on the wire — the demo client and `internal/testutil/webauthntest` show how to convert to and from `ArrayBuffer`.

### Authentication

| Method | Path                          | Description                                                       |
|--------|-------------------------------|-------------------------------------------------------------------|
| `POST` | `/auth/register/begin`        | Start registration. Body: `{ username, display_name }`            |
| `POST` | `/auth/register/complete`     | Verify attestation, store credential. Body: `{ session_id, credential }` |
| `POST` | `/auth/login/begin`           | Start discoverable login. No body                                 |
| `POST` | `/auth/login/complete`        | Verify assertion, set HttpOnly session cookie. Body: `{ session_id, credential }` |
| `POST` | `/auth/logout`                | Invalidate session, clear cookie. Idempotent                      |
| `POST` | `/auth/guest`                 | Create anonymous user + guest cookie. Idempotent                  |
| `POST` | `/auth/promote/begin`         | Start passkey registration for the current guest                  |
| `POST` | `/auth/promote/complete`      | Promote guest → registered + set session cookie                   |

### User

All `/users/me/*` require the session cookie (the `RequireSession` middleware).

| Method   | Path                          | Description                                       |
|----------|-------------------------------|---------------------------------------------------|
| `GET`    | `/users/me`                   | Profile: `{ user_id, username, display_name, is_guest }` |
| `GET`    | `/users/me/credentials`       | List of registered passkeys                       |
| `DELETE` | `/users/me/credentials/{id}`  | Soft-delete a passkey. 409 if it's the last one   |

### Health

| Method | Path                | Description                                  |
|--------|---------------------|----------------------------------------------|
| `GET`  | `/health`           | Liveness                                     |
| `GET`  | `/health/ready`     | Readiness: pings Postgres + Redis (503 if either down) |

### Error shape

```json
{ "code": "username_taken", "message": "That username is already registered." }
```

`code` is a stable machine-readable string. `message` is generic. Internal error details are logged server-side; they never appear in the body. The chokepoint is `internal/api/handler/response.go:writeError`.

---

## Spec decisions

These are the calls that separate a real WebAuthn implementation from a tutorial copy-paste. Each one has a why.

**Attestation: `none` preferred, every format accepted at the policy layer.** Most consumer passkeys (iCloud, Google, 1Password) return `none` by design — they're software authenticators that intentionally avoid revealing model identifiers. Requiring `direct` attestation would break the UX for everyone but hardware-key users. The library still verifies whatever format the authenticator does send; our `AcceptedAttestationFormats` map is the gate above. Both the format (`none`, `packed`, `tpm`, …) and the FIDO-registry attestation type (`none`, `basic_full`, `basic_surrogate`, …) are stored on the credential row so future operators can audit or tighten either axis without a migration.

**Challenge expiry: 5 minutes in Redis, deleted on first use.** Implemented via `GETDEL` (Redis ≥ 6.2). A captured session id cannot be replayed even within the validity window — a second `/complete` with the same id returns `401 session_invalid`. This is the WebAuthn replay-prevention contract.

**Sign-count anomaly logging.** The library enforces `new ≥ stored` rejection. We add structured warnings on top: counter reset (`stored > 0`, `new == 0`), AAGUID mismatch (registered model differs from asserted), backup-eligibility/state flip (synced ↔ device-bound). Strict equality rejection would break Apple/Google synced passkeys that always report 0; we accept those, but flag the anomalies that matter.

**AAGUID stored, never filtered.** Stored on the credential row, surfaced in `/users/me/credentials`. Filtering by AAGUID at registration time breaks legitimate cross-device flows; storing it allows future allow/deny-list policy.

**Resident keys / user verification: `preferred`, not `required`.** `required` breaks authenticators that don't support it. `preferred` gets us discoverable credentials and biometric UV when available without hard failures elsewhere.

**Conditional UI.** The demo client calls `navigator.credentials.get` with `mediation: "conditional"` on page load, and the username input has `autocomplete="username webauthn"`. On supported browsers (Safari 16+, Chrome 108+), passkeys surface in the autofill chip without a click.

**Opaque per-registration WebAuthn user handle.** The `user.id` sent to the authenticator is a fresh 64-byte random handle, stored on the credential row. **Not** the user's UUID — the WebAuthn handle is persisted on the authenticator and can be enumerated from it; using the DB UUID would leak a stable internal identifier.

**Backup-eligible / backup-state flags persisted.** Captured on every assertion. A credential that flips synced→device-bound (or vice versa) signals an account-recovery risk; surfacing it lets future policy act on it.

**Origin allowlist enforced.** `RP_ORIGINS` is the comma-separated allowlist of origins the library validates against during attestation and assertion. RP-ID matching alone permits any subdomain; an explicit allowlist catches misconfigured deployments.

**Session token in an HttpOnly cookie, never in any JSON body.** `/auth/login/complete` and `/auth/promote/complete` set `Set-Cookie: passkey_session=…; HttpOnly; Secure; SameSite=Lax` and return `{ user_id, username, display_name }` only. A response body is never the credential.

**Soft-delete + last-credential guard runs in a transaction.** `DELETE /users/me/credentials/{id}` calls `SoftDelete` which does `SELECT … FOR UPDATE`, counts live credentials, and refuses to set `deleted_at` if this would leave the user with zero. Two concurrent deletes cannot both succeed past the guard.

**Guest-session merging on first authentication.** If `/auth/login/complete` succeeds while a guest cookie is present, the guest token is dropped and the cookie cleared in the same response. In this MVP the merge is just cleanup; the seam is there for guest-owned state to be folded in later.

---

## Running locally

```bash
git clone https://github.com/rdaniel1105/go-passkey-auth
cd go-passkey-auth
cp .env.example .env
docker compose up           # postgres + redis + app on :8080
```

Migrations are applied automatically on startup. Then open `http://localhost:8080` in a browser that supports passkeys and exercise the demo.

For a host-mode run (Postgres + Redis in Docker, server on the host with `go run`):

```bash
docker compose up -d postgres redis
make migrate-up
make run                    # loads .env, listens on :8080
```

---

## Running tests

```bash
make test                   # unit + integration via testcontainers
```

Postgres and Redis are spun up by `testcontainers-go` on demand. Docker must be reachable; if it isn't, the integration tests `t.Skip` instead of failing.

The integration suite at `tests/integration` boots the full HTTP server in-process and drives every endpoint (register → login → me → list → delete guard → logout → guest → promote, plus a replay-protection check). The software authenticator at `internal/testutil/webauthntest` produces wire blobs that go-webauthn's library accepts on the same code path as production.

---

## What I'd add next

- **AAGUID policy.** Allowlist/denylist of authenticator models, configurable per relying party.
- **Rate limiting** on `/auth/*/begin` endpoints to prevent challenge farming.
- **Credential renaming.** The store already supports `Rename`; expose a `PATCH /users/me/credentials/{id}`.
- **`/.well-known/passkey-endpoints` discovery document.**
- **OpenAPI spec generated from handlers**, so the API surface has a machine-readable contract.
- **MFA fallback** for account recovery scenarios where the user has lost all their authenticators.
- **AAGUID → device-name lookup table** so the credentials list shows "iPhone" or "YubiKey 5C" instead of a UUID.
- **Step-up authentication** for sensitive operations — require a fresh assertion within N minutes for a `DELETE /credentials/{id}` of someone else's policy-critical key.

---

## License

MIT.
