-- 000001_init.up.sql
-- Initial schema: users + credentials.
--
-- Notes on a few non-obvious columns:
--   credentials.webauthn_user_handle  Opaque per-registration handle sent as
--                                     user.id to the authenticator. NOT the
--                                     internal user UUID -- using the UUID
--                                     leaks a stable identifier from the
--                                     authenticator.
--   credentials.backup_eligible / _state
--                                     The BE and BS flags from the
--                                     authenticator data. Persisted and
--                                     compared on every assertion so a
--                                     credential that flips synced↔single
--                                     device can be flagged.
--   credentials.deleted_at            Soft-delete. Hard-delete would let a
--                                     user re-register the same credential
--                                     id and break audit trails.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    is_guest      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    promoted_at   TIMESTAMPTZ
);

-- Allow multiple guests to share a placeholder username while keeping
-- registered usernames unique.
CREATE UNIQUE INDEX users_username_unique_registered
    ON users (username)
    WHERE is_guest = FALSE;

CREATE TABLE credentials (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id        BYTEA NOT NULL,
    public_key           BYTEA NOT NULL,
    webauthn_user_handle BYTEA NOT NULL,
    aaguid               UUID,
    sign_count           BIGINT NOT NULL DEFAULT 0,
    transports           TEXT[] NOT NULL DEFAULT '{}',
    attestation_format   TEXT NOT NULL DEFAULT 'none',
    attestation_type     TEXT NOT NULL DEFAULT 'none',
    backup_eligible      BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state         BOOLEAN NOT NULL DEFAULT FALSE,
    name                 TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at         TIMESTAMPTZ,
    deleted_at           TIMESTAMPTZ
);

-- credential_id must be globally unique among live (non-deleted) rows.
-- Allowing duplicates among soft-deleted rows preserves history.
CREATE UNIQUE INDEX credentials_credential_id_unique_live
    ON credentials (credential_id)
    WHERE deleted_at IS NULL;

CREATE INDEX credentials_user_id_live
    ON credentials (user_id)
    WHERE deleted_at IS NULL;
