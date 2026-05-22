// Package webauthntest is a software authenticator used by the integration
// tests to drive the WebAuthn ceremonies end-to-end without a real device.
//
// It produces wire-format attestation and assertion responses that the
// go-webauthn library validates against the same code path that runs in
// production. Attestation is "none" (i.e. self-attestation) — enough to
// exercise every server-side check (challenge, RP id, origin, sign count,
// BE/BS flags, AAGUID) without dragging in TPM emulation.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator is a single virtual passkey. It owns an EC P-256 key pair,
// an opaque credential id, and a sign counter that increments on every
// assertion (matching the spec's clone-detection contract).
type Authenticator struct {
	rpID   string
	origin string

	AAGUID [16]byte
	CredID []byte

	privKey *ecdsa.PrivateKey
	// signCount is the running sign counter. atomic so callers can run
	// concurrent assertions if they want, though tests usually serialise.
	signCount atomic.Uint32

	// BackupEligible / BackupState are the flags the authenticator advertises.
	// Defaults: BE=true, BS=true (i.e. behaves like a synced passkey).
	BackupEligible bool
	BackupState    bool
}

// New returns an Authenticator configured for the given RP id and origin.
// AAGUID and credential id are random; sign count starts at 0.
func New(rpID, origin string) (*Authenticator, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		return nil, fmt.Errorf("read credID: %w", err)
	}

	var aaguid [16]byte
	if _, err := rand.Read(aaguid[:]); err != nil {
		return nil, fmt.Errorf("read aaguid: %w", err)
	}

	return &Authenticator{
		rpID:           rpID,
		origin:         origin,
		AAGUID:         aaguid,
		CredID:         credID,
		privKey:        priv,
		BackupEligible: true,
		BackupState:    true,
	}, nil
}

// Register builds the wire-format credential response the client would
// return from navigator.credentials.create. challenge is the base64url
// string the server issued (matches the format the go-webauthn library
// stores in SessionData.Challenge).
func (a *Authenticator) Register(challenge string) (json.RawMessage, error) {
	clientDataJSON, err := buildClientDataJSON("webauthn.create", challenge, a.origin)
	if err != nil {
		return nil, err
	}

	authData, err := a.buildAuthData(true)
	if err != nil {
		return nil, err
	}

	attObj, err := encodeCBOR(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		return nil, fmt.Errorf("encode attestation object: %w", err)
	}

	credID64 := base64.RawURLEncoding.EncodeToString(a.CredID)

	return json.Marshal(map[string]any{
		"id":    credID64,
		"rawId": credID64,
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attObj),
		},
	})
}

// Authenticate builds the wire-format assertion response. challenge is
// the base64url string from SessionData.Challenge. userHandle is what the
// authenticator returns alongside the credential id during a discoverable
// login; the server uses it to look up the user.
func (a *Authenticator) Authenticate(challenge string, userHandle []byte) (json.RawMessage, error) {
	clientDataJSON, err := buildClientDataJSON("webauthn.get", challenge, a.origin)
	if err != nil {
		return nil, err
	}

	// Increment the sign counter before building authData so the server
	// sees a strictly monotonic value on each call.
	a.signCount.Add(1)

	authData, err := a.buildAuthData(false)
	if err != nil {
		return nil, err
	}

	clientDataHash := sha256.Sum256(clientDataJSON)
	toSign := make([]byte, 0, len(authData)+len(clientDataHash))
	toSign = append(toSign, authData...)
	toSign = append(toSign, clientDataHash[:]...)

	digest := sha256.Sum256(toSign)
	sig, err := ecdsa.SignASN1(rand.Reader, a.privKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign assertion: %w", err)
	}

	credID64 := base64.RawURLEncoding.EncodeToString(a.CredID)

	return json.Marshal(map[string]any{
		"id":    credID64,
		"rawId": credID64,
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
			"userHandle":        base64.RawURLEncoding.EncodeToString(userHandle),
		},
	})
}

// SignCount reports the current internal counter (one ahead after each
// successful Authenticate call).
func (a *Authenticator) SignCount() uint32 { return a.signCount.Load() }

// buildAuthData assembles the binary authenticatorData blob.
//
// Layout:
//
//	| rpIdHash (32) | flags (1) | signCount (4) |
//	| [attested credential data] | [extensions]    |
//
// For attestation (registration) the AT flag (0x40) is set and the
// attested-credential-data block follows. For assertion the block is
// omitted and the flag is clear.
func (a *Authenticator) buildAuthData(attested bool) ([]byte, error) {
	rpIDHash := sha256.Sum256([]byte(a.rpID))

	flags := byte(0x01 | 0x04) // UP | UV
	if a.BackupEligible {
		flags |= 0x08
	}

	if a.BackupState {
		flags |= 0x10
	}

	if attested {
		flags |= 0x40
	}

	buf := make([]byte, 0, 64)
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, flags)
	buf = binary.BigEndian.AppendUint32(buf, a.signCount.Load())

	if attested {
		pubKey, err := a.cosePublicKey()
		if err != nil {
			return nil, err
		}

		buf = append(buf, a.AAGUID[:]...)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(a.CredID)))
		buf = append(buf, a.CredID...)
		buf = append(buf, pubKey...)
	}

	return buf, nil
}

// cosePublicKey encodes the authenticator's public key as a COSE_Key CBOR
// map for ES256:
//
//	{1: 2, 3: -7, -1: 1, -2: x, -3: y}
//	  kty: EC2  alg: ES256  crv: P-256  x, y: 32-byte coords
//
// PublicKey.Bytes returns the uncompressed-point form (0x04 || X || Y) per
// SEC 1; for P-256 that's a fixed 65-byte layout from which we slice X and
// Y directly. This avoids reaching into the deprecated big.Int coords.
func (a *Authenticator) cosePublicKey() ([]byte, error) {
	raw, err := a.privKey.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}

	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("unexpected uncompressed point: len=%d, tag=0x%02x", len(raw), raw[0])
	}

	return encodeCBOR(map[int]any{
		1:  2,        // kty: EC2
		3:  -7,       // alg: ES256
		-1: 1,        // crv: P-256
		-2: raw[1:33],  // x
		-3: raw[33:65], // y
	})
}

// buildClientDataJSON renders the clientDataJSON. challenge is already a
// base64url string (the format the server stores in SessionData) — we
// embed it verbatim so byte-for-byte equality between client and server
// representations is preserved.
func buildClientDataJSON(typeStr, challenge, origin string) ([]byte, error) {
	clientData := map[string]any{
		"type":      typeStr,
		"challenge": challenge,
		"origin":    origin,
	}

	return json.Marshal(clientData)
}

func encodeCBOR(v any) ([]byte, error) {
	em, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("cbor encoder: %w", err)
	}

	return em.Marshal(v)
}
