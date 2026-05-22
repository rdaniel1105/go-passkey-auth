package webauthn

import (
	"testing"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/require"
)

func TestNewUserHandle_LengthAndEntropy(t *testing.T) {
	c := require.New(t)

	h, err := NewUserHandle()
	c.NoError(err)
	c.Len(h, UserHandleSize)

	// Generate enough handles that a collision would be vanishingly unlikely
	// unless rand is broken. 64 bytes * 64 samples = 64 * 2^64-ish entropy
	// space; if any two collide something is very wrong.
	seen := make(map[string]struct{}, 64)
	for range 64 {
		h, err := NewUserHandle()
		c.NoError(err)

		key := string(h)
		_, dup := seen[key]
		c.False(dup, "user handle collided")
		seen[key] = struct{}{}
	}
}

func TestUser_ImplementsWebAuthnUser(t *testing.T) {
	c := require.New(t)

	u := &User{
		Handle:      []byte{0x01, 0x02},
		Name:        "alice",
		DisplayName: "Alice",
	}

	// Compile-time check: *User must satisfy the library's User interface.
	var _ gowebauthn.User = u

	c.Equal([]byte{0x01, 0x02}, u.WebAuthnID())
	c.Equal("alice", u.WebAuthnName())
	c.Equal("Alice", u.WebAuthnDisplayName())
	c.Empty(u.WebAuthnCredentials())
}

func TestUser_CredentialsNilReturnsEmptySlice(t *testing.T) {
	c := require.New(t)

	u := &User{}

	// Library expects a non-nil slice; a nil slice would panic on len().
	creds := u.WebAuthnCredentials()
	c.NotNil(creds)
	c.Empty(creds)
}
