package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
	pkwebauthn "github.com/rdaniel1105/go-passkey-auth/internal/webauthn"
)

// --- fakes ---

type fakeUserStore struct {
	mu    sync.Mutex
	users map[uuid.UUID]*domain.User
	// nextErr, if set, is returned by the next CreateRegistered call.
	nextErr error
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{users: map[uuid.UUID]*domain.User{}}
}

func (s *fakeUserStore) CreateRegistered(_ context.Context, username, display string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.nextErr != nil {
		err := s.nextErr
		s.nextErr = nil
		return nil, err
	}

	for _, u := range s.users {
		if u.Username == username {
			return nil, domain.ErrUsernameTaken
		}
	}

	u := &domain.User{ID: uuid.New(), Username: username, DisplayName: display}
	s.users[u.ID] = u

	return u, nil
}

func (s *fakeUserStore) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}

	return u, nil
}

func (s *fakeUserStore) CreateGuest(_ context.Context, username, display string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u := &domain.User{ID: uuid.New(), Username: username, DisplayName: display, IsGuest: true}
	s.users[u.ID] = u

	return u, nil
}

func (s *fakeUserStore) PromoteGuest(_ context.Context, id uuid.UUID, username, display string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[id]
	if !ok || !u.IsGuest {
		return nil, domain.ErrUserNotFound
	}

	for _, other := range s.users {
		if other.ID != id && !other.IsGuest && other.Username == username {
			return nil, domain.ErrUsernameTaken
		}
	}

	u.Username = username
	u.DisplayName = display
	u.IsGuest = false
	now := time.Now()
	u.PromotedAt = &now

	return u, nil
}

type fakeCredentialStore struct {
	mu        sync.Mutex
	byID      map[string]*domain.Credential // keyed by credential_id hex
	byUser    map[uuid.UUID][]*domain.Credential
	inserts   []*domain.Credential
	insertErr error

	// updates records the (id, signCount, BE, BS) of each
	// UpdateAfterAssertion call so tests can verify counter writes.
	updates []credentialUpdate

	// softDeleteOverride, if set, replaces the default SoftDelete behavior
	// (which removes from byUser). Tests use it to inject ErrLastCredential
	// and similar.
	softDeleteOverride func(id uuid.UUID) error
}

type credentialUpdate struct {
	id        uuid.UUID
	signCount uint32
	be, bs    bool
}

func newFakeCredentialStore() *fakeCredentialStore {
	return &fakeCredentialStore{
		byID:   map[string]*domain.Credential{},
		byUser: map[uuid.UUID][]*domain.Credential{},
	}
}

func (s *fakeCredentialStore) Insert(_ context.Context, c *domain.Credential) (*domain.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.insertErr != nil {
		return nil, s.insertErr
	}

	c.ID = uuid.New()
	s.byID[string(c.CredentialID)] = c
	s.byUser[c.UserID] = append(s.byUser[c.UserID], c)
	s.inserts = append(s.inserts, c)

	return c, nil
}

func (s *fakeCredentialStore) GetByCredentialID(_ context.Context, credentialID []byte) (*domain.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.byID[string(credentialID)]
	if !ok {
		return nil, domain.ErrCredentialNotFound
	}

	return c, nil
}

func (s *fakeCredentialStore) ListByUserID(_ context.Context, userID uuid.UUID) ([]*domain.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]*domain.Credential(nil), s.byUser[userID]...), nil
}

func (s *fakeCredentialStore) UpdateAfterAssertion(_ context.Context, id uuid.UUID, signCount uint32, be, bs bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.updates = append(s.updates, credentialUpdate{id, signCount, be, bs})
	return nil
}

func (s *fakeCredentialStore) SoftDelete(_ context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.softDeleteOverride != nil {
		return s.softDeleteOverride(id)
	}

	for userID, list := range s.byUser {
		for i, c := range list {
			if c.ID == id {
				s.byUser[userID] = append(list[:i], list[i+1:]...)
				delete(s.byID, string(c.CredentialID))
				return nil
			}
		}
	}

	return domain.ErrCredentialNotFound
}

type fakeChallengeStore struct {
	mu      sync.Mutex
	entries map[string][]byte
}

func newFakeChallengeStore() *fakeChallengeStore {
	return &fakeChallengeStore{entries: map[string][]byte{}}
}

func (s *fakeChallengeStore) Save(_ context.Context, id string, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[id] = payload
	return nil
}

func (s *fakeChallengeStore) Take(_ context.Context, id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	payload, ok := s.entries[id]
	if !ok {
		return nil, domain.ErrChallengeNotFound
	}

	delete(s.entries, id)
	return payload, nil
}

type fakeWebAuthn struct {
	beginErr       error
	createErr      error
	createResult   *pkwebauthn.Credential
	beginLoginErr  error
	validateErr    error
	validateResult *pkwebauthn.Credential

	mu             sync.Mutex
	lastBeginUser  *pkwebauthn.User
	lastSessionID  string
	lastCreateUser *pkwebauthn.User
}

func (f *fakeWebAuthn) BeginRegistration(user *pkwebauthn.User, sessionID string) (*pkwebauthn.CreationOptions, *pkwebauthn.SessionData, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.beginErr != nil {
		return nil, nil, f.beginErr
	}

	f.lastBeginUser = user
	f.lastSessionID = sessionID

	session := &pkwebauthn.SessionData{
		Challenge: "test-challenge",
		UserID:    user.Handle,
	}

	return &pkwebauthn.CreationOptions{SessionID: sessionID}, session, nil
}

func (f *fakeWebAuthn) CreateCredential(user *pkwebauthn.User, _ pkwebauthn.SessionData, _ *pkwebauthn.ParsedCredentialCreationData) (*pkwebauthn.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.createErr != nil {
		return nil, f.createErr
	}

	f.lastCreateUser = user

	if f.createResult != nil {
		return f.createResult, nil
	}

	return &pkwebauthn.Credential{
		ID:                []byte{0xCA, 0xFE, 0xBA, 0xBE},
		PublicKey:         []byte{0xDE, 0xAD},
		AttestationFormat: "none",
		AttestationType:   "none",
	}, nil
}

func (f *fakeWebAuthn) ParseCredentialCreation(b []byte) (*pkwebauthn.ParsedCredentialCreationData, error) {
	// Smallest viable stub: any non-empty input parses to an empty struct.
	// Real validation happens in CreateCredential, which the fake controls.
	if len(b) == 0 {
		return nil, errors.New("empty credential")
	}

	return &pkwebauthn.ParsedCredentialCreationData{}, nil
}

func (f *fakeWebAuthn) ParseCredentialAssertion(b []byte) (*pkwebauthn.ParsedCredentialAssertionData, error) {
	// We only need RawID to flow through to the resolver. Parse just enough
	// JSON to extract it.
	var env struct {
		RawID string `json:"rawId"`
	}

	if err := json.Unmarshal(b, &env); err != nil || env.RawID == "" {
		return nil, errors.New("invalid assertion")
	}

	raw, err := base64.RawURLEncoding.DecodeString(env.RawID)
	if err != nil {
		return nil, err
	}

	var p pkwebauthn.ParsedCredentialAssertionData
	p.RawID = raw

	return &p, nil
}

func (f *fakeWebAuthn) BeginLogin(sessionID string) (*pkwebauthn.AssertionOptions, *pkwebauthn.SessionData, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.beginLoginErr != nil {
		return nil, nil, f.beginLoginErr
	}

	f.lastSessionID = sessionID
	return &pkwebauthn.AssertionOptions{SessionID: sessionID}, &pkwebauthn.SessionData{Challenge: "login-challenge"}, nil
}

func (f *fakeWebAuthn) ValidateLogin(handler pkwebauthn.DiscoverableUserHandler, _ pkwebauthn.SessionData, parsed *pkwebauthn.ParsedCredentialAssertionData) (*pkwebauthn.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.validateErr != nil {
		return nil, f.validateErr
	}

	// Invoke the resolver so the handler's lookup path runs.
	if handler != nil {
		if _, err := handler(parsed.RawID, nil); err != nil {
			return nil, err
		}
	}

	if f.validateResult != nil {
		return f.validateResult, nil
	}

	return &pkwebauthn.Credential{
		ID: parsed.RawID,
	}, nil
}

type fakeSessionStore struct {
	mu      sync.Mutex
	tokens  map[string]uuid.UUID
	created []string
	deleted []string
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{tokens: map[string]uuid.UUID{}}
}

func (s *fakeSessionStore) Create(_ context.Context, userID uuid.UUID) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token := "tok-" + uuid.NewString()
	s.tokens[token] = userID
	s.created = append(s.created, token)
	return token, nil
}

func (s *fakeSessionStore) Delete(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, token)
	s.deleted = append(s.deleted, token)
	return nil
}

type fakeGuestStore struct {
	mu      sync.Mutex
	tokens  map[string]uuid.UUID
	created []string
	deleted []string
}

func newFakeGuestStore() *fakeGuestStore {
	return &fakeGuestStore{tokens: map[string]uuid.UUID{}}
}

func (s *fakeGuestStore) Create(_ context.Context, userID uuid.UUID) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token := "gst-" + uuid.NewString()
	s.tokens[token] = userID
	s.created = append(s.created, token)
	return token, nil
}

func (s *fakeGuestStore) Get(_ context.Context, token string) (uuid.UUID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, ok := s.tokens[token]
	if !ok {
		return uuid.Nil, domain.ErrGuestNotFound
	}

	return id, nil
}

func (s *fakeGuestStore) Delete(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, token)
	s.deleted = append(s.deleted, token)
	return nil
}

// --- helpers ---

type testHarness struct {
	handler  *AuthHandler
	users    *fakeUserStore
	creds    *fakeCredentialStore
	chal     *fakeChallengeStore
	sessions *fakeSessionStore
	guests   *fakeGuestStore
	wa       *fakeWebAuthn
}

func newTestHandler(t *testing.T) *testHarness {
	t.Helper()

	h := &testHarness{
		users:    newFakeUserStore(),
		creds:    newFakeCredentialStore(),
		chal:     newFakeChallengeStore(),
		sessions: newFakeSessionStore(),
		guests:   newFakeGuestStore(),
		wa:       &fakeWebAuthn{},
	}

	h.handler = NewAuth(AuthDeps{
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WebAuthn:      h.wa,
		Users:         h.users,
		Credentials:   h.creds,
		Challenges:    h.chal,
		Sessions:      h.sessions,
		Guests:        h.guests,
		SessionMaxAge: 86400,
		GuestMaxAge:   3600,
	})

	return h
}

func postJSON(handler http.HandlerFunc, body any) *httptest.ResponseRecorder {
	var b bytes.Buffer
	_ = json.NewEncoder(&b).Encode(body)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", &b)
	req.Header.Set("Content-Type", "application/json")
	handler(rr, req)

	return rr
}

func decodeError(t *testing.T, rr *httptest.ResponseRecorder) errorBody {
	t.Helper()

	var body errorBody
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	return body
}

// --- BeginRegister ---

func TestBeginRegister_HappyPath(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	rr := postJSON(h.handler.BeginRegister, map[string]string{
		"username":     "alice",
		"display_name": "Alice",
	})
	c.Equal(http.StatusOK, rr.Code)

	// User row created.
	c.Len(h.users.users, 1)

	// Challenge session persisted.
	c.Len(h.chal.entries, 1)

	// WebAuthn called with the opaque handle, not the user UUID.
	c.NotNil(h.wa.lastBeginUser)
	c.Len(h.wa.lastBeginUser.Handle, pkwebauthn.UserHandleSize)
	c.Equal("alice", h.wa.lastBeginUser.Name)
}

func TestBeginRegister_InvalidJSON(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("not json")))
	h.handler.BeginRegister(rr, req)

	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_request", decodeError(t, rr).Code)
}

func TestBeginRegister_MissingFields(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	rr := postJSON(h.handler.BeginRegister, map[string]string{"username": "alice"})

	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("missing_fields", decodeError(t, rr).Code)
}

func TestBeginRegister_UsernameTaken(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	// First call succeeds.
	rr := postJSON(h.handler.BeginRegister, map[string]string{"username": "bob", "display_name": "Bob"})
	c.Equal(http.StatusOK, rr.Code)

	// Second call with same username -> 409.
	rr = postJSON(h.handler.BeginRegister, map[string]string{"username": "bob", "display_name": "Bob"})
	c.Equal(http.StatusConflict, rr.Code)
	c.Equal("username_taken", decodeError(t, rr).Code)
}

func TestBeginRegister_UserStoreError(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)
	h.users.nextErr = errors.New("db down")

	rr := postJSON(h.handler.BeginRegister, map[string]string{"username": "carol", "display_name": "Carol"})

	c.Equal(http.StatusInternalServerError, rr.Code)
	c.Equal("internal_error", decodeError(t, rr).Code)
}

// --- CompleteRegister ---

func TestCompleteRegister_SessionNotFound(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	rr := postJSON(h.handler.CompleteRegister, map[string]any{
		"session_id": "missing",
		"credential": json.RawMessage(`{}`),
	})

	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("session_invalid", decodeError(t, rr).Code)
}

func TestCompleteRegister_MissingFields(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	rr := postJSON(h.handler.CompleteRegister, map[string]any{"session_id": ""})

	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("missing_fields", decodeError(t, rr).Code)
}

func TestCompleteRegister_InvalidJSON(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("not json")))
	h.handler.CompleteRegister(rr, req)

	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_request", decodeError(t, rr).Code)
}

func TestCompleteRegister_SessionConsumedOnceOnly(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	// Seed a stored registration session.
	userID := uuid.New()
	payload, err := json.Marshal(registrationSession{
		UserID:  userID,
		Session: pkwebauthn.SessionData{Challenge: "x", UserID: []byte("handle")},
	})
	c.NoError(err)
	c.NoError(h.chal.Save(context.Background(), "sess-x", payload))

	// We don't have a real credential JSON, so the first call will fail at
	// parse — but the important thing is that the challenge was consumed.
	rr := postJSON(h.handler.CompleteRegister, map[string]any{
		"session_id": "sess-x",
		"credential": json.RawMessage(`{"id":"not real"}`),
	})
	c.NotEqual(http.StatusOK, rr.Code) // any non-2xx is fine here

	// Second attempt against the same session id must now report
	// session_invalid — replay protection.
	rr = postJSON(h.handler.CompleteRegister, map[string]any{
		"session_id": "sess-x",
		"credential": json.RawMessage(`{}`),
	})
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("session_invalid", decodeError(t, rr).Code)
}

// --- BeginLogin ---

func TestBeginLogin_HappyPath(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	rr := postJSON(h.handler.BeginLogin, struct{}{})
	c.Equal(http.StatusOK, rr.Code)

	c.Len(h.chal.entries, 1)
	c.NotEmpty(h.wa.lastSessionID)
	_, ok := h.chal.entries[h.wa.lastSessionID]
	c.True(ok, "session not stored under the id passed to webauthn")
}

func TestBeginLogin_WebAuthnError(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)
	h.wa.beginLoginErr = errors.New("library down")

	rr := postJSON(h.handler.BeginLogin, struct{}{})
	c.Equal(http.StatusInternalServerError, rr.Code)
	c.Equal("internal_error", decodeError(t, rr).Code)
}

// --- CompleteLogin ---

// seedLogin stores a login session and a credential row that resolves to
// userID. credentialID is what the (fake) assertion will report as RawID.
func seedLogin(t *testing.T, h *testHarness, sessionID string, userID uuid.UUID, credentialID []byte, signCount uint32) {
	t.Helper()

	c := require.New(t)

	user, err := h.users.CreateRegistered(context.Background(), "u-"+uuid.NewString(), "User")
	c.NoError(err)

	h.users.mu.Lock()
	delete(h.users.users, user.ID)
	user.ID = userID
	h.users.users[userID] = user
	h.users.mu.Unlock()

	_, err = h.creds.Insert(context.Background(), &domain.Credential{
		UserID:             userID,
		CredentialID:       credentialID,
		PublicKey:          []byte{0x01},
		WebAuthnUserHandle: []byte("handle"),
		SignCount:          signCount,
		AttestationFormat:  "none",
		AttestationType:    "none",
	})
	c.NoError(err)

	payload, err := json.Marshal(loginSession{Session: pkwebauthn.SessionData{Challenge: "ch"}})
	c.NoError(err)
	c.NoError(h.chal.Save(context.Background(), sessionID, payload))
}

// credentialJSON builds an attestation-response JSON whose top-level
// rawId base64-url-decodes to want.
func credentialJSON(want []byte) json.RawMessage {
	rawIDB64 := base64.RawURLEncoding.EncodeToString(want)
	return json.RawMessage(`{"id":"` + rawIDB64 +
		`","rawId":"` + rawIDB64 +
		`","type":"public-key","response":{"clientDataJSON":"","authenticatorData":"","signature":""}}`)
}

func TestCompleteLogin_SessionNotFound(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	rr := postJSON(h.handler.CompleteLogin, map[string]any{
		"session_id": "missing",
		"credential": json.RawMessage(`{}`),
	})
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("session_invalid", decodeError(t, rr).Code)
}

func TestCompleteLogin_MissingFields(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	rr := postJSON(h.handler.CompleteLogin, map[string]any{"session_id": ""})
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("missing_fields", decodeError(t, rr).Code)
}

func TestCompleteLogin_HappyPath(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	userID := uuid.New()
	credentialID := []byte{0xCA, 0xFE}
	seedLogin(t, h, "sess-login", userID, credentialID, 5)

	h.wa.validateResult = &pkwebauthn.Credential{
		ID: credentialID,
		Authenticator: pkwebauthn.Authenticator{
			SignCount: 7,
		},
		Flags: pkwebauthn.CredentialFlags{
			BackupEligible: true,
			BackupState:    true,
		},
	}

	rr := postJSON(h.handler.CompleteLogin, map[string]any{
		"session_id": "sess-login",
		"credential": credentialJSON(credentialID),
	})
	c.Equal(http.StatusOK, rr.Code)

	c.Len(h.sessions.created, 1)

	cookies := rr.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, ck := range cookies {
		if ck.Name == SessionCookieName {
			sessionCookie = ck
		}
	}
	c.NotNil(sessionCookie)
	c.Equal(h.sessions.created[0], sessionCookie.Value)
	c.True(sessionCookie.HttpOnly)
	c.Equal(http.SameSiteLaxMode, sessionCookie.SameSite)

	// JSON body does NOT contain the token — it lives only in the cookie.
	c.NotContains(rr.Body.String(), sessionCookie.Value)

	// Counter and flags updated.
	c.Len(h.creds.updates, 1)
	c.Equal(uint32(7), h.creds.updates[0].signCount)
	c.True(h.creds.updates[0].be)
	c.True(h.creds.updates[0].bs)
}

func TestCompleteLogin_CredentialNotFound(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	payload, err := json.Marshal(loginSession{Session: pkwebauthn.SessionData{Challenge: "ch"}})
	c.NoError(err)
	c.NoError(h.chal.Save(context.Background(), "sess-none", payload))

	rr := postJSON(h.handler.CompleteLogin, map[string]any{
		"session_id": "sess-none",
		"credential": credentialJSON([]byte{0x99}),
	})
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("unauthorized", decodeError(t, rr).Code)
}

// --- Logout ---

func TestLogout_ClearsCookieAndDeletesSession(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "tok-abc"})

	h.handler.Logout(rr, req)
	c.Equal(http.StatusNoContent, rr.Code)
	c.Equal([]string{"tok-abc"}, h.sessions.deleted)

	var cleared bool
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == SessionCookieName && ck.MaxAge < 0 {
			cleared = true
		}
	}
	c.True(cleared, "session cookie not cleared")
}

func TestLogout_NoCookie_NoOp(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)

	h.handler.Logout(rr, req)
	c.Equal(http.StatusNoContent, rr.Code)
	c.Empty(h.sessions.deleted)
}
