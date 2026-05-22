// Package domain holds the core entities used across the service: User,
// Credential, and the sentinel errors returned by the store layer.
package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Sentinel errors returned by stores. Use errors.Is to match.
var (
	// ErrUserNotFound is returned when a user lookup finds no row.
	ErrUserNotFound = errors.New("user not found")
	// ErrCredentialNotFound is returned when a credential lookup finds no
	// live row (soft-deleted rows are treated as not found).
	ErrCredentialNotFound = errors.New("credential not found")
	// ErrUsernameTaken is returned when registering a non-guest user with a
	// username that already exists.
	ErrUsernameTaken = errors.New("username already taken")
	// ErrCredentialExists is returned when a credential_id is already
	// registered to a live credential row.
	ErrCredentialExists = errors.New("credential already registered")
	// ErrLastCredential is returned when a delete would remove the user's
	// only remaining live credential. The caller must require the user to
	// register a replacement first.
	ErrLastCredential = errors.New("cannot delete the last credential")
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
