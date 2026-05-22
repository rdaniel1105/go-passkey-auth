package webauthntest

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	pkwebauthn "github.com/rdaniel1105/go-passkey-auth/internal/webauthn"
)

// TestRegister_ParsesViaLibrary verifies that the wire bytes the
// authenticator produces are accepted by go-webauthn's parser — i.e. our
// COSE / CBOR / JSON encoding is correct enough to flow through the same
// path the production handler uses.
func TestRegister_ParsesViaLibrary(t *testing.T) {
	c := require.New(t)

	a, err := New("localhost", "http://localhost:8080")
	c.NoError(err)

	svc, err := pkwebauthn.NewService(pkwebauthn.Config{
		RPID:            "localhost",
		RPDisplayName:   "test",
		RPOrigins:       []string{"http://localhost:8080"},
		CeremonyTimeout: 60_000_000_000, // 60s in ns
	})
	c.NoError(err)

	// Build a registration request the way our handler does.
	handle := make([]byte, pkwebauthn.UserHandleSize)
	_, err = rand.Read(handle)
	c.NoError(err)

	user := &pkwebauthn.User{Handle: handle, Name: "alice", DisplayName: "Alice"}

	options, session, err := svc.BeginRegistration(user, "sess-x")
	c.NoError(err)
	c.NotNil(options)
	c.NotNil(session)

	credResp, err := a.Register(session.Challenge)
	c.NoError(err)

	parsed, err := svc.ParseCredentialCreation(credResp)
	c.NoError(err)
	c.Equal(a.CredID, []byte(parsed.RawID))

	// Run it through the full attestation verifier.
	cred, err := svc.CreateCredential(user, *session, parsed)
	c.NoError(err)
	c.Equal(a.CredID, cred.ID)
	c.Equal("none", cred.AttestationFormat)
}

// TestAuthenticate_ParsesAndVerifies covers the assertion path: build an
// assertion, send it through the library validator, expect the credential
// to come back with the new sign count.
func TestAuthenticate_ParsesAndVerifies(t *testing.T) {
	c := require.New(t)

	a, err := New("localhost", "http://localhost:8080")
	c.NoError(err)

	svc, err := pkwebauthn.NewService(pkwebauthn.Config{
		RPID:            "localhost",
		RPDisplayName:   "test",
		RPOrigins:       []string{"http://localhost:8080"},
		CeremonyTimeout: 60_000_000_000,
	})
	c.NoError(err)

	// Register so we have a credential to authenticate against.
	handle := make([]byte, pkwebauthn.UserHandleSize)
	_, err = rand.Read(handle)
	c.NoError(err)

	user := &pkwebauthn.User{Handle: handle, Name: "alice", DisplayName: "Alice"}

	_, regSession, err := svc.BeginRegistration(user, "sess-r")
	c.NoError(err)

	credResp, err := a.Register(regSession.Challenge)
	c.NoError(err)

	parsedReg, err := svc.ParseCredentialCreation(credResp)
	c.NoError(err)

	registered, err := svc.CreateCredential(user, *regSession, parsedReg)
	c.NoError(err)

	// Now start an assertion ceremony.
	_, loginSession, err := svc.BeginLogin("sess-l")
	c.NoError(err)

	assertion, err := a.Authenticate(loginSession.Challenge, handle)
	c.NoError(err)

	parsedAssert, err := svc.ParseCredentialAssertion(assertion)
	c.NoError(err)

	// Provide the registered credential to the resolver so the library
	// can match by id.
	resolver := func(_, _ []byte) (pkwebauthn.LibUser, error) {
		userWithCred := &pkwebauthn.User{
			Handle:      handle,
			Name:        user.Name,
			DisplayName: user.DisplayName,
			Credentials: []pkwebauthn.Credential{*registered},
		}
		return userWithCred, nil
	}

	asserted, err := svc.ValidateLogin(resolver, *loginSession, parsedAssert)
	c.NoError(err)
	c.Equal(a.CredID, asserted.ID)
	c.Equal(uint32(1), asserted.Authenticator.SignCount)
}
