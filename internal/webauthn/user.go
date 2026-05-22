package webauthn

import (
	"crypto/rand"
	"fmt"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// UserHandleSize is the byte length of the opaque WebAuthn user handle. The
// spec recommends 64 bytes maximum; we use the full 64 to maximise entropy
// while staying within authenticator-supported limits.
const UserHandleSize = 64

// NewUserHandle returns a freshly generated, cryptographically random user
// handle. This is the value sent to the authenticator as user.id during
// registration — NOT the internal user UUID. See PRD §7.
func NewUserHandle() ([]byte, error) {
	b := make([]byte, UserHandleSize)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate user handle: %w", err)
	}

	return b, nil
}

// User adapts our domain user (plus an opaque WebAuthn handle and any
// existing credentials) to the go-webauthn library's User interface.
//
// For a fresh registration, Credentials is nil and the handle is freshly
// generated. For authentication of a known user, Credentials is the list
// fetched from the credential store, and Handle is the handle that was
// stored alongside the credential being asserted against.
type User struct {
	Handle      []byte
	Name        string
	DisplayName string
	Credentials []gowebauthn.Credential
}

// WebAuthnID returns the opaque handle.
func (u *User) WebAuthnID() []byte { return u.Handle }

// WebAuthnName returns the username shown to the user during the ceremony.
func (u *User) WebAuthnName() string { return u.Name }

// WebAuthnDisplayName returns the display name shown to the user.
func (u *User) WebAuthnDisplayName() string { return u.DisplayName }

// WebAuthnCredentials returns the user's existing credentials, or an empty
// slice if they have none (e.g. during initial registration).
func (u *User) WebAuthnCredentials() []gowebauthn.Credential {
	if u.Credentials == nil {
		return []gowebauthn.Credential{}
	}

	return u.Credentials
}
