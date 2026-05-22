// Package domain holds the core entities used across the service (User,
// Credential) and the sentinel errors returned by the store layer.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// User is a registered or guest user. Guests have is_guest = true and no
// promoted_at; once promoted via a passkey registration, is_guest flips to
// false and promoted_at is set.
type User struct {
	ID          uuid.UUID
	Username    string
	DisplayName string
	IsGuest     bool
	CreatedAt   time.Time
	PromotedAt  *time.Time
}

// Credential is a single registered passkey. WebAuthnUserHandle is the
// opaque per-registration handle that was sent to the authenticator as
// user.id; it is NOT the user UUID. Using the UUID would leak a stable
// internal identifier through the authenticator.
//
// Two attestation columns track the two axes WebAuthn separates:
//   - AttestationFormat is the wire format ("none", "packed", "tpm",
//     "android-key", "android-safetynet", "fido-u2f", "apple").
//   - AttestationType is the trust relationship ("none", "basic_full",
//     "basic_surrogate", "attca", "anonca", "ecdaa").
//
// Both are validated against the policy sets in the webauthn package on
// registration and stored here so future operators can audit or tighten
// either axis without a migration.
type Credential struct {
	ID                 uuid.UUID
	UserID             uuid.UUID
	CredentialID       []byte
	PublicKey          []byte
	WebAuthnUserHandle []byte
	AAGUID             *uuid.UUID
	SignCount          uint32
	Transports         []string
	AttestationFormat  string
	AttestationType    string
	BackupEligible     bool
	BackupState        bool
	Name               *string
	CreatedAt          time.Time
	LastUsedAt         *time.Time
}
