package webauthn

// Attestation policy, per PRD §7.
//
// The WebAuthn spec defines several attestation formats: "none", "packed",
// "tpm", "android-key", "android-safetynet", "fido-u2f", and "apple". Each
// format is a different way for the authenticator to prove its identity to
// the relying party at registration time.
//
// We default to "none" (PreferNoAttestation set in NewService) because:
//   - Consumer passkeys (iCloud Keychain, Google Password Manager,
//     1Password, Bitwarden) return "none" by design — they are software
//     authenticators that intentionally avoid revealing model identifiers
//     to RPs to protect user privacy.
//   - Requiring "direct" attestation would force users to confirm an
//     "additional information will be shared" dialog and would *break*
//     authenticators that cannot or will not provide it.
//   - For our threat model (a portfolio service), the AAGUID alone tells us
//     what model registered, and storing it lets a future operator add
//     allowlist/denylist policy on top without re-architecting.
//
// The go-webauthn library still verifies whichever format the authenticator
// chooses to send — we don't disable verification. We just don't demand a
// specific one. The format actually used is recorded on the credential row
// as attestation_type so we can audit and, later, enforce policy.

// AcceptedAttestationFormats is the set of attestation formats the service
// will accept on FinishRegistration. The library verifies each format's
// signature independently; this list is the policy layer above it.
//
// "none" and "packed" are the two formats called out in the PRD. "packed"
// covers most hardware security keys (YubiKey, Titan) and is the closest
// thing to a standard. The others are accepted because rejecting them
// would break legitimate authenticators (e.g. Android phones can return
// "android-key" or "android-safetynet"). If future policy needs to restrict
// the set, narrow this list rather than introducing a new code path.
var AcceptedAttestationFormats = map[string]struct{}{
	"none":              {},
	"packed":            {},
	"tpm":               {},
	"android-key":       {},
	"android-safetynet": {},
	"fido-u2f":          {},
	"apple":             {},
}

// IsAcceptedAttestation reports whether the given format string is in the
// accepted set. Empty string is treated as "none".
func IsAcceptedAttestation(format string) bool {
	if format == "" {
		format = "none"
	}

	_, ok := AcceptedAttestationFormats[format]
	return ok
}
