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
	CreateGuest(ctx context.Context, username, displayName string) (*domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	PromoteGuest(ctx context.Context, id uuid.UUID, username, displayName string) (*domain.User, error)
}

// credentialStore is the slice of CredentialStore the auth handler depends on.
type credentialStore interface {
	Insert(ctx context.Context, c *domain.Credential) (*domain.Credential, error)
	GetByCredentialID(ctx context.Context, credentialID []byte) (*domain.Credential, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Credential, error)
	UpdateAfterAssertion(ctx context.Context, id uuid.UUID, signCount uint32, backupEligible, backupState bool) error
}

// challengeStore is the slice of ChallengeStore the auth handler depends on.
type challengeStore interface {
	Save(ctx context.Context, sessionID string, payload []byte) error
	Take(ctx context.Context, sessionID string) ([]byte, error)
}

// sessionStore is the slice of SessionStore the auth handler depends on.
type sessionStore interface {
	Create(ctx context.Context, userID uuid.UUID) (string, error)
	Delete(ctx context.Context, token string) error
}

// guestStore is the slice of GuestStore the auth handler depends on. Guest
// tokens live in a separate redis namespace from session tokens — they
// cannot cross-resolve.
type guestStore interface {
	Create(ctx context.Context, userID uuid.UUID) (string, error)
	Get(ctx context.Context, token string) (uuid.UUID, error)
	Delete(ctx context.Context, token string) error
}

// webauthnService is the slice of *webauthn.Service the auth handler uses.
// Parsing of the raw JSON credential bytes goes through the service (rather
// than via package-level helpers) so unit tests can stub the parser; only
// the integration tests need to roundtrip real attestation/assertion data.
type webauthnService interface {
	BeginRegistration(user *pkwebauthn.User, sessionID string) (*pkwebauthn.CreationOptions, *pkwebauthn.SessionData, error)
	ParseCredentialCreation(b []byte) (*pkwebauthn.ParsedCredentialCreationData, error)
	CreateCredential(user *pkwebauthn.User, session pkwebauthn.SessionData, parsed *pkwebauthn.ParsedCredentialCreationData) (*pkwebauthn.Credential, error)
	BeginLogin(sessionID string) (*pkwebauthn.AssertionOptions, *pkwebauthn.SessionData, error)
	ParseCredentialAssertion(b []byte) (*pkwebauthn.ParsedCredentialAssertionData, error)
	ValidateLogin(handler pkwebauthn.DiscoverableUserHandler, session pkwebauthn.SessionData, parsed *pkwebauthn.ParsedCredentialAssertionData) (*pkwebauthn.Credential, error)
}

// AuthDeps bundles the collaborators the AuthHandler needs.
type AuthDeps struct {
	Logger      *slog.Logger
	WebAuthn    webauthnService
	Users       userStore
	Credentials credentialStore
	Challenges  challengeStore
	Sessions    sessionStore
	Guests      guestStore
	// SessionMaxAge is how long the issued session cookie lives.
	SessionMaxAge int
	// GuestMaxAge is how long the issued guest cookie lives.
	GuestMaxAge int
}

// AuthHandler implements the /auth/* endpoints.
type AuthHandler struct {
	logger        *slog.Logger
	webauthn      webauthnService
	users         userStore
	credentials   credentialStore
	challenges    challengeStore
	sessions      sessionStore
	guests        guestStore
	sessionMaxAge int
	guestMaxAge   int
}

// registrationSession is the payload stored in the challenge store between
// /register/begin and /register/complete (or /promote/begin and
// /promote/complete). It bundles the library's SessionData with our
// internal user UUID so /complete can find the already-created user row
// without trusting any client-provided id.
//
// Promote = true marks a session originated from /promote/begin. The
// matching /promote/complete refuses the session if it was not, and vice
// versa, so a client cannot cross-flow.
type registrationSession struct {
	UserID         uuid.UUID              `json:"user_id"`
	Session        pkwebauthn.SessionData `json:"session"`
	Promote        bool                   `json:"promote,omitempty"`
	PromoteName    string                 `json:"promote_name,omitempty"`
	PromoteDisplay string                 `json:"promote_display,omitempty"`
}

type beginRegisterRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

type beginPromoteRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

type guestResponse struct {
	UserID string `json:"user_id"`
}

type completeRegisterRequest struct {
	SessionID  string          `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

type completeRegisterResponse struct {
	CredentialID string `json:"credential_id"`
}

// loginSession is the payload stored in the challenge store between
// /login/begin and /login/complete. We only need the library SessionData
// because the user is unknown until the authenticator responds (that's
// the whole point of discoverable login).
type loginSession struct {
	Session pkwebauthn.SessionData `json:"session"`
}

type completeLoginRequest struct {
	SessionID  string          `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

type completeLoginResponse struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

// NewAuth constructs an AuthHandler from its dependencies.
func NewAuth(deps AuthDeps) *AuthHandler {
	return &AuthHandler{
		logger:        deps.Logger,
		webauthn:      deps.WebAuthn,
		users:         deps.Users,
		credentials:   deps.Credentials,
		challenges:    deps.Challenges,
		sessions:      deps.Sessions,
		guests:        deps.Guests,
		sessionMaxAge: deps.SessionMaxAge,
		guestMaxAge:   deps.GuestMaxAge,
	}
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

	if stored.Promote {
		// Session was minted by /promote/begin — must go through
		// /promote/complete. Refuse to handle it here.
		writeError(w, h.logger, http.StatusUnauthorized, "session_invalid")
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

	parsed, err := h.webauthn.ParseCredentialCreation(req.Credential)
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
		AttestationFormat:  cred.AttestationFormat,
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

// --- Login ---

// BeginLogin handles POST /auth/login/begin.
//
// No request body is required — discoverable login does not specify a user
// up front. The client should call navigator.credentials.get with
// mediation: "conditional" (autofill) or "required" (explicit) using these
// options.
func (h *AuthHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	sessionID, err := newSessionID()
	if err != nil {
		h.logger.Error("login: session id", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	options, session, err := h.webauthn.BeginLogin(sessionID)
	if err != nil {
		h.logger.Error("login: webauthn begin", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	payload, err := json.Marshal(loginSession{Session: *session})
	if err != nil {
		h.logger.Error("login: marshal session", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	if err := h.challenges.Save(r.Context(), sessionID, payload); err != nil {
		h.logger.Error("login: save challenge", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	writeJSON(w, h.logger, http.StatusOK, options)
}

// CompleteLogin handles POST /auth/login/complete.
//
// Flow:
//  1. Decode the envelope { session_id, credential }.
//  2. Atomically GET+DEL the challenge session.
//  3. Parse the assertion response.
//  4. Validate via webauthn.ValidateLogin, resolving the user via a callback
//     that hits credentialStore.GetByCredentialID and userStore.GetByID.
//  5. Apply sign-count and AAGUID anomaly logging (PRD §7).
//  6. UpdateAfterAssertion writes the new counter and BE/BS flags.
//  7. Issue a session token, write it to the HttpOnly cookie. The token is
//     NEVER returned in the JSON body (PRD §13).
func (h *AuthHandler) CompleteLogin(w http.ResponseWriter, r *http.Request) {
	var req completeLoginRequest
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
		h.logger.Error("login complete: take challenge", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	var stored loginSession
	if err := json.Unmarshal(raw, &stored); err != nil {
		h.logger.Error("login complete: unmarshal session", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	parsed, err := h.webauthn.ParseCredentialAssertion(req.Credential)
	if err != nil {
		h.logger.Warn("login complete: parse credential", "err", err)
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request")
		return
	}

	// resolved holds the domain values we look up inside the resolver so we
	// can act on them after the library returns. The library only gives us
	// back its own *Credential type.
	var (
		resolvedUser *domain.User
		resolvedCred *domain.Credential
	)

	var resolver pkwebauthn.DiscoverableUserHandler = func(_, _ []byte) (pkwebauthn.LibUser, error) {
		dbCred, err := h.credentials.GetByCredentialID(r.Context(), parsed.RawID)
		if err != nil {
			return nil, err
		}

		dbUser, err := h.users.GetByID(r.Context(), dbCred.UserID)
		if err != nil {
			return nil, err
		}

		resolvedUser = dbUser
		resolvedCred = dbCred

		libCred, err := libCredentialFromDomain(dbCred)
		if err != nil {
			return nil, err
		}

		return &pkwebauthn.User{
			Handle:      dbCred.WebAuthnUserHandle,
			Name:        dbUser.Username,
			DisplayName: dbUser.DisplayName,
			Credentials: []pkwebauthn.Credential{*libCred},
		}, nil
	}

	cred, err := h.webauthn.ValidateLogin(resolver, stored.Session, parsed)
	if err != nil {
		h.logger.Warn("login complete: validate", "err", err)
		writeError(w, h.logger, http.StatusUnauthorized, "unauthorized")
		return
	}

	if resolvedCred == nil || resolvedUser == nil {
		h.logger.Error("login complete: resolver bypassed", "credential_id", parsed.RawID)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	h.recordCounterAnomalies(resolvedCred, cred)

	if err := h.credentials.UpdateAfterAssertion(
		r.Context(),
		resolvedCred.ID,
		cred.Authenticator.SignCount,
		cred.Flags.BackupEligible,
		cred.Flags.BackupState,
	); err != nil {
		h.logger.Error("login complete: update credential", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	token, err := h.sessions.Create(r.Context(), resolvedUser.ID)
	if err != nil {
		h.logger.Error("login complete: create session", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	setSessionCookie(w, r, token, h.sessionMaxAge)

	// Guest-session merging on first authentication (PRD §13). If the
	// request arrives with a guest cookie, the user has just authenticated
	// as a registered user — drop the guest token and clear the cookie.
	// "Guest-owned state" beyond the user row does not exist in this MVP,
	// so the merge is effectively just this cleanup.
	if gc, err := r.Cookie(GuestCookieName); err == nil && gc.Value != "" {
		if err := h.guests.Delete(r.Context(), gc.Value); err != nil {
			h.logger.Warn("login complete: delete guest", "err", err)
		}

		clearGuestCookie(w, r)
	}

	writeJSON(w, h.logger, http.StatusOK, completeLoginResponse{
		UserID:      resolvedUser.ID.String(),
		Username:    resolvedUser.Username,
		DisplayName: resolvedUser.DisplayName,
	})
}

// Logout handles POST /auth/logout. Idempotent — a missing or invalid
// cookie is not treated as an error; the response is always 204.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		if err := h.sessions.Delete(r.Context(), cookie.Value); err != nil {
			h.logger.Warn("logout: delete session", "err", err)
		}
	}

	clearSessionCookie(w, r)
	w.WriteHeader(http.StatusNoContent)
}

// --- Guest + promotion ---

// Guest handles POST /auth/guest. Creates an anonymous user row, mints a
// guest token, sets the guest cookie, and returns the new user id.
//
// If the request already has a guest cookie that resolves to a live user,
// we reuse it instead of creating a new one — so repeated /guest calls
// from the same browser stay idempotent.
func (h *AuthHandler) Guest(w http.ResponseWriter, r *http.Request) {
	if gc, err := r.Cookie(GuestCookieName); err == nil && gc.Value != "" {
		if userID, err := h.guests.Get(r.Context(), gc.Value); err == nil {
			if user, err := h.users.GetByID(r.Context(), userID); err == nil && user.IsGuest {
				writeJSON(w, h.logger, http.StatusOK, guestResponse{UserID: user.ID.String()})
				return
			}
		}
	}

	username := "guest-" + uuid.NewString()
	user, err := h.users.CreateGuest(r.Context(), username, "Guest")
	if err != nil {
		h.logger.Error("guest: create user", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	token, err := h.guests.Create(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("guest: mint token", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	setGuestCookie(w, r, token, h.guestMaxAge)
	writeJSON(w, h.logger, http.StatusOK, guestResponse{UserID: user.ID.String()})
}

// BeginPromote handles POST /auth/promote/begin. Like BeginRegister, but
// the user already exists (as a guest) — we keep their UUID, just ask the
// authenticator to register a credential against an opaque handle. The
// chosen username + display_name are persisted in the registration session
// so /promote/complete can apply them inside PromoteGuest.
func (h *AuthHandler) BeginPromote(w http.ResponseWriter, r *http.Request) {
	var req beginPromoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request")
		return
	}

	if req.Username == "" || req.DisplayName == "" {
		writeError(w, h.logger, http.StatusBadRequest, "missing_fields")
		return
	}

	guest, ok := h.resolveGuest(r)
	if !ok {
		writeError(w, h.logger, http.StatusUnauthorized, "guest_invalid")
		return
	}

	if !guest.IsGuest {
		writeError(w, h.logger, http.StatusConflict, "not_a_guest")
		return
	}

	handle, err := pkwebauthn.NewUserHandle()
	if err != nil {
		h.logger.Error("promote: user handle", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	sessionID, err := newSessionID()
	if err != nil {
		h.logger.Error("promote: session id", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	waUser := &pkwebauthn.User{
		Handle:      handle,
		Name:        req.Username,
		DisplayName: req.DisplayName,
	}

	options, session, err := h.webauthn.BeginRegistration(waUser, sessionID)
	if err != nil {
		h.logger.Error("promote: webauthn begin", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	payload, err := json.Marshal(registrationSession{
		UserID:         guest.ID,
		Session:        *session,
		Promote:        true,
		PromoteName:    req.Username,
		PromoteDisplay: req.DisplayName,
	})
	if err != nil {
		h.logger.Error("promote: marshal session", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	if err := h.challenges.Save(r.Context(), sessionID, payload); err != nil {
		h.logger.Error("promote: save challenge", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	writeJSON(w, h.logger, http.StatusOK, options)
}

// CompletePromote handles POST /auth/promote/complete.
//
// Flow:
//  1. Decode envelope, take the challenge.
//  2. Refuse cross-flow: the session must have been created by BeginPromote.
//  3. Verify attestation against the stored SessionData.
//  4. PromoteGuest — atomic check that the row is still a guest. Returns
//     ErrUsernameTaken if someone claimed the username concurrently.
//  5. Insert the credential.
//  6. Clear the guest cookie, issue a session cookie. The user is logged
//     in immediately, the same way /login/complete leaves them.
func (h *AuthHandler) CompletePromote(w http.ResponseWriter, r *http.Request) {
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
		h.logger.Error("promote complete: take challenge", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	var stored registrationSession
	if err := json.Unmarshal(raw, &stored); err != nil {
		h.logger.Error("promote complete: unmarshal session", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	if !stored.Promote {
		// Session was minted by /register/begin — refuse to handle it here.
		writeError(w, h.logger, http.StatusUnauthorized, "session_invalid")
		return
	}

	waUser := &pkwebauthn.User{
		Handle:      []byte(stored.Session.UserID),
		Name:        stored.PromoteName,
		DisplayName: stored.PromoteDisplay,
	}

	parsed, err := h.webauthn.ParseCredentialCreation(req.Credential)
	if err != nil {
		h.logger.Warn("promote complete: parse credential", "err", err)
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request")
		return
	}

	cred, err := h.webauthn.CreateCredential(waUser, stored.Session, parsed)
	if errors.Is(err, pkwebauthn.ErrAttestationNotAccepted) {
		writeError(w, h.logger, http.StatusBadRequest, "attestation_rejected")
		return
	}

	if err != nil {
		h.logger.Warn("promote complete: verify attestation", "err", err)
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request")
		return
	}

	promoted, err := h.users.PromoteGuest(r.Context(), stored.UserID, stored.PromoteName, stored.PromoteDisplay)
	if errors.Is(err, domain.ErrUsernameTaken) {
		writeError(w, h.logger, http.StatusConflict, "username_taken")
		return
	}

	if errors.Is(err, domain.ErrUserNotFound) {
		// Either the user was deleted or they're no longer a guest.
		writeError(w, h.logger, http.StatusConflict, "not_a_guest")
		return
	}

	if err != nil {
		h.logger.Error("promote complete: promote user", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	domainCred, err := domainCredentialFromLib(promoted.ID, waUser.Handle, cred)
	if err != nil {
		h.logger.Error("promote complete: convert credential", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	if _, err := h.credentials.Insert(r.Context(), domainCred); err != nil {
		if errors.Is(err, domain.ErrCredentialExists) {
			writeError(w, h.logger, http.StatusConflict, "credential_exists")
			return
		}

		h.logger.Error("promote complete: insert credential", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	token, err := h.sessions.Create(r.Context(), promoted.ID)
	if err != nil {
		h.logger.Error("promote complete: create session", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	// Drop the guest token + cookie now that the user is registered and
	// holding a real session cookie.
	if gc, err := r.Cookie(GuestCookieName); err == nil && gc.Value != "" {
		if err := h.guests.Delete(r.Context(), gc.Value); err != nil {
			h.logger.Warn("promote complete: delete guest", "err", err)
		}

		clearGuestCookie(w, r)
	}

	setSessionCookie(w, r, token, h.sessionMaxAge)

	writeJSON(w, h.logger, http.StatusOK, completeLoginResponse{
		UserID:      promoted.ID.String(),
		Username:    promoted.Username,
		DisplayName: promoted.DisplayName,
	})
}

// resolveGuest reads the guest cookie and returns the user row it points
// to. The boolean is false on any failure (no cookie, expired token,
// deleted user, store error).
func (h *AuthHandler) resolveGuest(r *http.Request) (*domain.User, bool) {
	gc, err := r.Cookie(GuestCookieName)
	if err != nil || gc.Value == "" {
		return nil, false
	}

	userID, err := h.guests.Get(r.Context(), gc.Value)
	if err != nil {
		return nil, false
	}

	user, err := h.users.GetByID(r.Context(), userID)
	if err != nil {
		return nil, false
	}

	return user, true
}

// recordCounterAnomalies emits structured warnings for the security events
// PRD §7 calls out. The actual rejection of new < stored is enforced by the
// library before we get here; what we add is visibility on the *unusual*
// cases that the library accepts but a human should know about.
func (h *AuthHandler) recordCounterAnomalies(stored *domain.Credential, asserted *pkwebauthn.Credential) {
	newCount := asserted.Authenticator.SignCount

	// Counter reset: stored was non-zero, new is zero. Often a sign the
	// authenticator was wiped and re-provisioned.
	if stored.SignCount > 0 && newCount == 0 {
		h.logger.Warn("passkey counter reset",
			"credential_id", stored.ID,
			"user_id", stored.UserID,
			"stored_count", stored.SignCount,
		)
	}

	// AAGUID mismatch: the asserted credential reports a different model
	// than the registration did. Should not normally happen.
	if stored.AAGUID != nil && len(asserted.Authenticator.AAGUID) > 0 {
		storedID := *stored.AAGUID
		assertedID, err := uuid.FromBytes(asserted.Authenticator.AAGUID)
		if err == nil && storedID != assertedID {
			h.logger.Warn("passkey aaguid mismatch",
				"credential_id", stored.ID,
				"user_id", stored.UserID,
				"stored_aaguid", storedID,
				"asserted_aaguid", assertedID,
			)
		}
	}

	// Backup eligibility/state flip: a credential switching from synced to
	// device-bound (or vice versa) is worth flagging.
	if stored.BackupEligible != asserted.Flags.BackupEligible ||
		stored.BackupState != asserted.Flags.BackupState {
		h.logger.Warn("passkey backup flags changed",
			"credential_id", stored.ID,
			"user_id", stored.UserID,
			"stored_be", stored.BackupEligible, "stored_bs", stored.BackupState,
			"asserted_be", asserted.Flags.BackupEligible, "asserted_bs", asserted.Flags.BackupState,
		)
	}
}

// libCredentialFromDomain reconstructs the library's Credential type from
// our domain.Credential so the discoverable-login resolver can return a
// User with a credentials slice for the library to match against.
func libCredentialFromDomain(c *domain.Credential) (*pkwebauthn.Credential, error) {
	out := &pkwebauthn.Credential{
		ID:        c.CredentialID,
		PublicKey: c.PublicKey,
		Flags: pkwebauthn.CredentialFlags{
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: pkwebauthn.Authenticator{
			SignCount: c.SignCount,
		},
	}

	if c.AAGUID != nil {
		out.Authenticator.AAGUID = c.AAGUID[:]
	}

	for _, t := range c.Transports {
		out.Transport = append(out.Transport, pkwebauthn.AuthenticatorTransport(t))
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
