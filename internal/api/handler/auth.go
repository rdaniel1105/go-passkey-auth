package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
	pkwebauthn "github.com/rdaniel1105/go-passkey-auth/internal/webauthn"
)

// userStore is the slice of UserStore the auth handler depends on. Lets the
// tests substitute a fake without dragging in the full pgx pool.
type userStore interface {
	CreateRegistered(ctx context.Context, username, displayName string) (*domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

// credentialStore is the slice of CredentialStore the auth handler depends on.
type credentialStore interface {
	Insert(ctx context.Context, c *domain.Credential) (*domain.Credential, error)
}

// challengeStore is the slice of ChallengeStore the auth handler depends on.
type challengeStore interface {
	Save(ctx context.Context, sessionID string, payload []byte) error
	Take(ctx context.Context, sessionID string) ([]byte, error)
}

// webauthnService is the slice of *webauthn.Service the auth handler uses.
type webauthnService interface {
	BeginRegistration(user *pkwebauthn.User, sessionID string) (*pkwebauthn.CreationOptions, *pkwebauthn.SessionData, error)
	CreateCredential(user *pkwebauthn.User, session pkwebauthn.SessionData, parsed *pkwebauthn.ParsedCredentialCreationData) (*pkwebauthn.Credential, error)
}

// AuthDeps bundles the collaborators the AuthHandler needs.
type AuthDeps struct {
	Logger      *slog.Logger
	WebAuthn    webauthnService
	Users       userStore
	Credentials credentialStore
	Challenges  challengeStore
}

// AuthHandler implements the /auth/* endpoints.
type AuthHandler struct {
	logger      *slog.Logger
	webauthn    webauthnService
	users       userStore
	credentials credentialStore
	challenges  challengeStore
}

// NewAuth constructs an AuthHandler from its dependencies.
func NewAuth(deps AuthDeps) *AuthHandler {
	return &AuthHandler{
		logger:      deps.Logger,
		webauthn:    deps.WebAuthn,
		users:       deps.Users,
		credentials: deps.Credentials,
		challenges:  deps.Challenges,
	}
}

// registrationSession is the payload stored in the challenge store between
// /register/begin and /register/complete. It bundles the library's
// SessionData with our internal user UUID so /complete can find the
// already-created user row without trusting any client-provided id.
type registrationSession struct {
	UserID  uuid.UUID              `json:"user_id"`
	Session pkwebauthn.SessionData `json:"session"`
}

type beginRegisterRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

// BeginRegister handles POST /auth/register/begin.
//
// Flow:
//  1. Validate the request body (username + display_name).
//  2. Insert a fresh registered user row.
//  3. Generate an opaque 64-byte WebAuthn user handle (NOT the user UUID).
//  4. Ask the webauthn service to build CreationOptions + SessionData.
//  5. Persist SessionData + our user UUID in the challenge store keyed by
//     a fresh session id (one-shot consume on /complete).
//  6. Return the CreationOptions to the client.
func (h *AuthHandler) BeginRegister(w http.ResponseWriter, r *http.Request) {
	var req beginRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request")
		return
	}

	if req.Username == "" || req.DisplayName == "" {
		writeError(w, h.logger, http.StatusBadRequest, "missing_fields")
		return
	}

	user, err := h.users.CreateRegistered(r.Context(), req.Username, req.DisplayName)
	if errors.Is(err, domain.ErrUsernameTaken) {
		writeError(w, h.logger, http.StatusConflict, "username_taken")
		return
	}

	if err != nil {
		h.logger.Error("register: create user", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	handle, err := pkwebauthn.NewUserHandle()
	if err != nil {
		h.logger.Error("register: user handle", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	sessionID, err := newSessionID()
	if err != nil {
		h.logger.Error("register: session id", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	waUser := &pkwebauthn.User{
		Handle:      handle,
		Name:        user.Username,
		DisplayName: user.DisplayName,
	}

	options, session, err := h.webauthn.BeginRegistration(waUser, sessionID)
	if err != nil {
		h.logger.Error("register: webauthn begin", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	payload, err := json.Marshal(registrationSession{
		UserID:  user.ID,
		Session: *session,
	})
	if err != nil {
		h.logger.Error("register: marshal session", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	if err := h.challenges.Save(r.Context(), sessionID, payload); err != nil {
		h.logger.Error("register: save challenge", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	writeJSON(w, h.logger, http.StatusOK, options)
}

type completeRegisterRequest struct {
	SessionID  string          `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

type completeRegisterResponse struct {
	CredentialID string `json:"credential_id"`
}

// CompleteRegister handles POST /auth/register/complete.
//
// Flow:
//  1. Decode the envelope { session_id, credential }.
//  2. Atomically GET+DEL the challenge session by id (replay protection).
//  3. Parse the credential bytes via the webauthn service.
//  4. Verify the attestation against the SessionData.
//  5. Persist the credential row.
func (h *AuthHandler) CompleteRegister(w http.ResponseWriter, r *http.Request) {
	var req completeRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request")
		return
	}

	if req.SessionID == "" || len(req.Credential) == 0 {
		writeError(w, h.logger, http.StatusBadRequest, "missing_fields")
		return
	}

	raw, err := h.challenges.Take(r.Context(), req.SessionID)
	if errors.Is(err, domain.ErrChallengeNotFound) {
		writeError(w, h.logger, http.StatusUnauthorized, "session_invalid")
		return
	}

	if err != nil {
		h.logger.Error("register complete: take challenge", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	var stored registrationSession
	if err := json.Unmarshal(raw, &stored); err != nil {
		h.logger.Error("register complete: unmarshal session", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	user, err := h.users.GetByID(r.Context(), stored.UserID)
	if err != nil {
		h.logger.Error("register complete: get user", "err", err, "user_id", stored.UserID)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	waUser := &pkwebauthn.User{
		Handle:      []byte(stored.Session.UserID),
		Name:        user.Username,
		DisplayName: user.DisplayName,
	}

	parsed, err := pkwebauthn.ParseCredentialCreation(req.Credential)
	if err != nil {
		h.logger.Warn("register complete: parse credential", "err", err)
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request")
		return
	}

	cred, err := h.webauthn.CreateCredential(waUser, stored.Session, parsed)
	if errors.Is(err, pkwebauthn.ErrAttestationNotAccepted) {
		writeError(w, h.logger, http.StatusBadRequest, "attestation_rejected")
		return
	}

	if err != nil {
		h.logger.Warn("register complete: verify attestation", "err", err)
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request")
		return
	}

	domainCred, err := domainCredentialFromLib(stored.UserID, waUser.Handle, cred)
	if err != nil {
		h.logger.Error("register complete: convert credential", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	saved, err := h.credentials.Insert(r.Context(), domainCred)
	if errors.Is(err, domain.ErrCredentialExists) {
		writeError(w, h.logger, http.StatusConflict, "credential_exists")
		return
	}

	if err != nil {
		h.logger.Error("register complete: insert credential", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	writeJSON(w, h.logger, http.StatusOK, completeRegisterResponse{
		CredentialID: saved.ID.String(),
	})
}

// domainCredentialFromLib converts the go-webauthn credential type into our
// domain.Credential, parsing AAGUID and pulling through the BE/BS flags.
func domainCredentialFromLib(userID uuid.UUID, handle []byte, cred *pkwebauthn.Credential) (*domain.Credential, error) {
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}

	out := &domain.Credential{
		UserID:             userID,
		CredentialID:       cred.ID,
		PublicKey:          cred.PublicKey,
		WebAuthnUserHandle: handle,
		SignCount:          cred.Authenticator.SignCount,
		Transports:         transports,
		AttestationType:    cred.AttestationType,
		BackupEligible:     cred.Flags.BackupEligible,
		BackupState:        cred.Flags.BackupState,
	}

	if len(cred.Authenticator.AAGUID) > 0 {
		id, err := uuid.FromBytes(cred.Authenticator.AAGUID)
		if err != nil {
			return nil, fmt.Errorf("parse aaguid: %w", err)
		}

		out.AAGUID = &id
	}

	return out, nil
}

// newSessionID returns a URL-safe random string used as the challenge key.
func newSessionID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
