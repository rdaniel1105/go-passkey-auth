// Package webauthn wraps github.com/go-webauthn/webauthn with the spec
// decisions documented in PRD §7: opaque user handles, residentKey/UV
// preferred (not required), `none` attestation preferred, and explicit
// origin allowlisting.
package webauthn

import (
	"errors"
	"fmt"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/go-webauthn/webauthn/protocol"
)

// Config configures a Service. Origins are the explicit allowlist the
// underlying library enforces during attestation and assertion verification.
type Config struct {
	// RPID is the Relying Party identifier (registrable domain, no scheme).
	RPID string
	// RPDisplayName is the human-readable name shown by browsers.
	RPDisplayName string
	// RPOrigins is the explicit allowlist of acceptable origins.
	RPOrigins []string
	// CeremonyTimeout is the maximum time the browser will wait for the user
	// to interact with their authenticator. Should match the challenge TTL.
	CeremonyTimeout time.Duration
}

// Sentinel errors returned by NewService when Config is invalid.
var (
	ErrConfigMissingRPID          = errors.New("webauthn: RPID is required")
	ErrConfigMissingRPDisplayName = errors.New("webauthn: RPDisplayName is required")
	ErrConfigMissingRPOrigins     = errors.New("webauthn: at least one RPOrigin is required")
	ErrConfigInvalidTimeout       = errors.New("webauthn: CeremonyTimeout must be positive")
)

// NewService constructs a Service from Config. Returns a sentinel error if
// any required field is missing.
//
// Spec decisions baked in here, per PRD §7:
//   - AttestationPreference = "none": maximises compatibility with consumer
//     passkeys (iCloud Keychain, Google Password Manager, 1Password). The
//     library still verifies whatever attestation format the authenticator
//     does send, but we don't *demand* "direct" attestation — that breaks
//     most hardware keys and phones.
//   - ResidentKey = "preferred" and UserVerification = "preferred": "required"
//     breaks authenticators that don't support it; "preferred" gets us
//     discoverable credentials and biometric UV when available without hard
//     failures elsewhere.
func NewService(cfg Config) (*Service, error) {
	switch {
	case cfg.RPID == "":
		return nil, ErrConfigMissingRPID
	case cfg.RPDisplayName == "":
		return nil, ErrConfigMissingRPDisplayName
	case len(cfg.RPOrigins) == 0:
		return nil, ErrConfigMissingRPOrigins
	case cfg.CeremonyTimeout <= 0:
		return nil, ErrConfigInvalidTimeout
	}

	wcfg := &gowebauthn.Config{
		RPID:                  cfg.RPID,
		RPDisplayName:         cfg.RPDisplayName,
		RPOrigins:             cfg.RPOrigins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		},
		Timeouts: gowebauthn.TimeoutsConfig{
			Registration: gowebauthn.TimeoutConfig{
				Enforce: true,
				Timeout: cfg.CeremonyTimeout,
			},
			Login: gowebauthn.TimeoutConfig{
				Enforce: true,
				Timeout: cfg.CeremonyTimeout,
			},
		},
	}

	w, err := gowebauthn.New(wcfg)
	if err != nil {
		return nil, fmt.Errorf("webauthn init: %w", err)
	}

	return &Service{web: w}, nil
}

// Service drives the WebAuthn ceremonies. It is safe for concurrent use.
type Service struct {
	web *gowebauthn.WebAuthn
}
