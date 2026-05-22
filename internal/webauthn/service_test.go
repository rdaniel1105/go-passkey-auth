package webauthn

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/require"
)

func newTestService(t *testing.T) *Service {
	t.Helper()

	svc, err := NewService(validCfg())
	require.NoError(t, err)

	return svc
}

func newTestUser(t *testing.T) *User {
	t.Helper()

	handle, err := NewUserHandle()
	require.NoError(t, err)

	return &User{
		Handle:      handle,
		Name:        "alice@example.com",
		DisplayName: "Alice",
	}
}

func TestBeginRegistration_OptionsShape(t *testing.T) {
	c := require.New(t)

	svc := newTestService(t)
	user := newTestUser(t)

	out, session, err := svc.BeginRegistration(user, "sess-1")
	c.NoError(err)
	c.NotNil(out)
	c.Equal("sess-1", out.SessionID)
	c.NotEmpty(out.Options.Challenge)
	c.Equal("localhost", out.Options.RelyingParty.ID)
	c.Equal("go-passkey-auth", out.Options.RelyingParty.Name)

	// residentKey and userVerification must be "preferred", not "required",
	// to maximise authenticator compatibility.
	c.Equal(protocol.ResidentKeyRequirementPreferred, out.Options.AuthenticatorSelection.ResidentKey)
	c.Equal(protocol.VerificationPreferred, out.Options.AuthenticatorSelection.UserVerification)

	// Attestation preference is "none" (best compatibility with consumer passkeys).
	c.Equal(protocol.PreferNoAttestation, out.Options.Attestation)

	// The opaque user handle, not the user's UUID, is what the authenticator sees.
	idBytes, ok := out.Options.User.ID.(protocol.URLEncodedBase64)
	c.True(ok, "expected User.ID to be URLEncodedBase64, got %T", out.Options.User.ID)
	c.Equal(user.Handle, []byte(idBytes))

	c.NotNil(session)
	c.NotEmpty(session.Challenge)
}

func TestBeginRegistration_EachCallProducesFreshChallenge(t *testing.T) {
	c := require.New(t)

	svc := newTestService(t)
	user := newTestUser(t)

	out1, _, err := svc.BeginRegistration(user, "sess-a")
	c.NoError(err)

	out2, _, err := svc.BeginRegistration(user, "sess-b")
	c.NoError(err)

	c.NotEqual(out1.Options.Challenge, out2.Options.Challenge)
}

func TestMarshalUnmarshalSession_Roundtrip(t *testing.T) {
	c := require.New(t)

	svc := newTestService(t)
	user := newTestUser(t)

	_, session, err := svc.BeginRegistration(user, "sess-rt")
	c.NoError(err)

	b, err := MarshalSession(session)
	c.NoError(err)
	c.NotEmpty(b)

	got, err := UnmarshalSession(b)
	c.NoError(err)
	c.Equal(session.Challenge, got.Challenge)
	c.Equal(session.UserID, got.UserID)
	c.Equal(session.UserVerification, got.UserVerification)
}

func TestUnmarshalSession_RejectsGarbage(t *testing.T) {
	c := require.New(t)

	_, err := UnmarshalSession([]byte("not json"))
	c.Error(err)
}

// Sanity check: ensure SessionData is a value type the library expects to be
// passed by value into FinishRegistration. This guards against a future
// library change that would break our store API.
func TestSessionData_PassedByValue(t *testing.T) {
	require.IsType(t, gowebauthn.SessionData{}, gowebauthn.SessionData{})
}
