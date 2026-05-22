package webauthn

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// ErrAttestationNotAccepted is returned by FinishRegistration when the
// authenticator returns an attestation format not in AcceptedAttestationFormats.
var ErrAttestationNotAccepted = errors.New("webauthn: attestation format not accepted")

// ErrAttestationTypeNotAccepted is returned when the authenticator returns
// an attestation *type* (trust relationship) not in AcceptedAttestationTypes.
var ErrAttestationTypeNotAccepted = errors.New("webauthn: attestation type not accepted")

// Type aliases re-exported so callers can stay decoupled from the
// underlying library packages. These are aliases (not new types) so values
// flow freely between this package and the library.
type (
	// SessionData is the per-ceremony state created by Begin and consumed by
	// Finish. JSON-marshallable.
	SessionData = gowebauthn.SessionData
	// Credential is the validated credential returned by FinishRegistration
	// or FinishLogin.
	Credential = gowebauthn.Credential
	// ParsedCredentialCreationData is the typed view of a parsed attestation
	// response, produced by ParseCredentialCreation.
	ParsedCredentialCreationData = protocol.ParsedCredentialCreationData
	// ParsedCredentialAssertionData is the typed view of a parsed assertion
	// response, produced by ParseCredentialAssertion.
	ParsedCredentialAssertionData = protocol.ParsedCredentialAssertionData
	// DiscoverableUserHandler is the callback the library invokes during a
	// discoverable (passkey) login to resolve the user that owns the
	// credential. It takes the raw credential id and the userHandle from
	// the authenticator response and must return a User.
	DiscoverableUserHandler = gowebauthn.DiscoverableUserHandler
	// LibUser is the library's User interface — what handlers must produce
	// inside a DiscoverableUserHandler. *User in this package satisfies it.
	LibUser = gowebauthn.User
	// CredentialFlags is the BE/BS flags blob stored on a Credential.
	CredentialFlags = gowebauthn.CredentialFlags
	// Authenticator is the authenticator metadata on a Credential
	// (AAGUID, sign count, attachment, etc.).
	Authenticator = gowebauthn.Authenticator
	// AuthenticatorTransport is one of usb, nfc, ble, hybrid, internal, etc.
	AuthenticatorTransport = protocol.AuthenticatorTransport
)

// CreationOptions is the wire payload returned from BeginRegistration:
// the public-key options the browser passes to navigator.credentials.create,
// plus the session id the caller will use to retrieve the SessionData blob
// on the corresponding /complete call.
type CreationOptions struct {
	Options   *protocol.PublicKeyCredentialCreationOptions `json:"options"`
	SessionID string                                       `json:"session_id"`
}

// BeginRegistration starts a registration ceremony for user. The returned
// CreationOptions is what the HTTP handler returns to the client; the
// SessionData blob must be persisted (via ChallengeStore.Save) under
// SessionID so it can be retrieved on /complete.
//
// The caller is responsible for:
//   - Generating SessionID (an opaque random string, e.g. the same kind of
//     handle used elsewhere).
//   - Persisting MarshalSession(session) under SessionID with the
//     ChallengeTTL.
func (s *Service) BeginRegistration(user *User, sessionID string) (*CreationOptions, *gowebauthn.SessionData, error) {
	creation, session, err := s.web.BeginRegistration(user)
	if err != nil {
		return nil, nil, fmt.Errorf("begin registration: %w", err)
	}

	if session == nil {
		return nil, nil, errors.New("webauthn: nil session data")
	}

	return &CreationOptions{
		Options:   &creation.Response,
		SessionID: sessionID,
	}, session, nil
}

// FinishRegistration verifies an attestation response read directly from an
// *http.Request body and returns the validated credential. Convenience for
// handlers that don't need an envelope around the credential.
//
// session must be the SessionData previously stored at BeginRegistration
// and just consumed via ChallengeStore.Take (one-shot replay protection).
//
// Returns ErrAttestationNotAccepted if the format is outside the policy set
// in AcceptedAttestationFormats.
func (s *Service) FinishRegistration(user *User, session gowebauthn.SessionData, r *http.Request) (*gowebauthn.Credential, error) {
	cred, err := s.web.FinishRegistration(user, session, r)
	if err != nil {
		return nil, fmt.Errorf("finish registration: %w", err)
	}

	if err := checkAttestationPolicy(cred); err != nil {
		return nil, err
	}

	return cred, nil
}

// CreateCredential is the parsed-response counterpart to FinishRegistration.
// Use it when the wire format is a JSON envelope like
// {"session_id":"...","credential":{...}}: decode the envelope in the
// handler, then call ParseCredentialCreation on the inner credential bytes
// and hand the parsed value here.
func (s *Service) CreateCredential(user *User, session gowebauthn.SessionData, parsed *protocol.ParsedCredentialCreationData) (*gowebauthn.Credential, error) {
	cred, err := s.web.CreateCredential(user, session, parsed)
	if err != nil {
		return nil, fmt.Errorf("create credential: %w", err)
	}

	if err := checkAttestationPolicy(cred); err != nil {
		return nil, err
	}

	return cred, nil
}

// checkAttestationPolicy applies both axes of policy: the wire format and
// the trust-relationship type (see AcceptedAttestationFormats /
// AcceptedAttestationTypes).
func checkAttestationPolicy(cred *gowebauthn.Credential) error {
	if !IsAcceptedAttestation(cred.AttestationFormat) {
		return fmt.Errorf("%w: %q", ErrAttestationNotAccepted, cred.AttestationFormat)
	}

	if !IsAcceptedAttestationType(cred.AttestationType) {
		return fmt.Errorf("%w: %q", ErrAttestationTypeNotAccepted, cred.AttestationType)
	}

	return nil
}

// ParseCredentialCreation parses a raw JSON credential creation response
// (the `credential` field of the wire envelope) into the library's typed
// form. Surfaces parse errors to the caller; no policy applied here.
//
// Exposed on the Service (rather than as a package-level function) so
// handler unit tests can stub the parser without rebuilding a full
// attestation blob.
func (s *Service) ParseCredentialCreation(b []byte) (*protocol.ParsedCredentialCreationData, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(b)
	if err != nil {
		return nil, fmt.Errorf("parse credential creation response: %w", err)
	}

	return parsed, nil
}

// AssertionOptions is the wire payload returned from BeginLogin: the
// public-key options the browser passes to navigator.credentials.get, plus
// the session id used to retrieve the SessionData blob on /complete.
type AssertionOptions struct {
	Options   *protocol.PublicKeyCredentialRequestOptions `json:"options"`
	SessionID string                                      `json:"session_id"`
}

// BeginLogin starts a discoverable (passkey) login ceremony. The browser is
// expected to call navigator.credentials.get with mediation: "conditional"
// for autofill UX (PRD §7), or mediation: "required" for an explicit click.
// Either way, the server-side options are the same — the mediation flag is
// a client concern.
//
// The returned SessionData must be persisted (via ChallengeStore.Save)
// under SessionID so it can be retrieved on /complete.
func (s *Service) BeginLogin(sessionID string) (*AssertionOptions, *gowebauthn.SessionData, error) {
	assertion, session, err := s.web.BeginDiscoverableLogin()
	if err != nil {
		return nil, nil, fmt.Errorf("begin login: %w", err)
	}

	if session == nil {
		return nil, nil, errors.New("webauthn: nil session data")
	}

	return &AssertionOptions{
		Options:   &assertion.Response,
		SessionID: sessionID,
	}, session, nil
}

// ValidateLogin verifies an assertion response from a discoverable login.
// The handler callback is invoked with the credential id and user handle
// from the response and must return the User who owns the credential
// (including the credentials slice so the library can match by id).
func (s *Service) ValidateLogin(handler DiscoverableUserHandler, session gowebauthn.SessionData, parsed *protocol.ParsedCredentialAssertionData) (*gowebauthn.Credential, error) {
	cred, err := s.web.ValidateDiscoverableLogin(handler, session, parsed)
	if err != nil {
		return nil, fmt.Errorf("validate login: %w", err)
	}

	return cred, nil
}

// ParseCredentialAssertion parses a raw JSON assertion response (the
// `credential` field of the wire envelope). Exposed on Service so handler
// unit tests can stub the parser.
func (s *Service) ParseCredentialAssertion(b []byte) (*protocol.ParsedCredentialAssertionData, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(b)
	if err != nil {
		return nil, fmt.Errorf("parse credential assertion response: %w", err)
	}

	return parsed, nil
}

// MarshalSession serialises a SessionData for ChallengeStore.Save.
func MarshalSession(s *gowebauthn.SessionData) ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshal session: %w", err)
	}

	return b, nil
}

// UnmarshalSession reverses MarshalSession.
func UnmarshalSession(b []byte) (*gowebauthn.SessionData, error) {
	var s gowebauthn.SessionData
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	return &s, nil
}
