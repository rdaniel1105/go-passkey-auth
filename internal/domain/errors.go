package domain

import "errors"

// Sentinel errors returned by the store layer. Use errors.Is to match.
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

	// ErrSessionNotFound is returned when a session token cannot be resolved
	// in Redis (expired, never existed, or already invalidated).
	ErrSessionNotFound = errors.New("session not found")
	// ErrChallengeNotFound is returned when a WebAuthn challenge cannot be
	// resolved. Challenges are one-shot: after a successful Take they are
	// gone, so a second attempt to consume the same id is treated as a
	// replay and returns this sentinel.
	ErrChallengeNotFound = errors.New("challenge not found")
	// ErrGuestNotFound is returned when a guest token cannot be resolved.
	ErrGuestNotFound = errors.New("guest session not found")
)
