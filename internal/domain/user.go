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

// Credential is a single registered passkey. WebAuthnUserHandle is the opaque
// per-registration handle that was sent to the authenticator as user.id; it
// is NOT the user UUID. See PRD §7.
type Credential struct {
	ID                 uuid.UUID
	UserID             uuid.UUID
	CredentialID       []byte
	PublicKey          []byte
	WebAuthnUserHandle []byte
	AAGUID             *uuid.UUID
	SignCount          uint32
	Transports         []string
	AttestationType    string
	BackupEligible     bool
	BackupState        bool
	Name               *string
	CreatedAt          time.Time
	LastUsedAt         *time.Time
}
