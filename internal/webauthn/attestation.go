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

// AcceptedAttestationTypes is the second axis of attestation policy.
//
// WebAuthn separates two things:
//   - format ("packed", "tpm", "none", …) — how the statement is encoded.
//   - type  ("basic_full", "basic_surrogate", …) — the trust relationship
//     between the signing key and the authenticator model.
//
// Library docs and the FIDO registry call out these type values, returned
// by *Credential.AttestationType after FinishRegistration:
//
//   - basic_full       — per-model batch attestation key signs the public
//                        key. Strongest cryptographic proof of model.
//   - basic_surrogate  — self-attestation: the credential signs itself.
//                        No proof of model. The default for most consumer
//                        passkeys (iCloud Keychain, Google Password
//                        Manager) that intentionally avoid revealing
//                        device fingerprints.
//   - attca            — PrivacyCA attestation (TCG style, mostly TPM).
//   - anonca           — Anonymisation CA. Privacy-preserving group
//                        attestation (Android SafetyNet/Keystore, Apple).
//   - ecdaa            — Direct anonymous attestation. Optional and rare
//                        in practice.
//   - none             — No attestation at all.
//
// We accept every value the library can return for the same reason we
// accept every format: the library has already verified cryptographically
// whatever is verifiable; this set is the policy gate above. Future
// operators tightening policy (e.g. for high-assurance accounts) should
// narrow this list — typically by dropping basic_surrogate to require a
// proof of model.
var AcceptedAttestationTypes = map[string]struct{}{
	"none":            {},
	"basic_full":      {},
	"basic_surrogate": {},
	"attca":           {},
	"anonca":          {},
	"ecdaa":           {},
}

// IsAcceptedAttestationType reports whether the given attestation type is
// in the accepted set. Empty string is treated as "none".
func IsAcceptedAttestationType(t string) bool {
	if t == "" {
		t = "none"
	}

	_, ok := AcceptedAttestationTypes[t]
	return ok
}
