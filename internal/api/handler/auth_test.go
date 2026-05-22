package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

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

type fakeCredentialStore struct {
	mu        sync.Mutex
	inserts   []*domain.Credential
	insertErr error
}

func (s *fakeCredentialStore) Insert(_ context.Context, c *domain.Credential) (*domain.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.insertErr != nil {
		return nil, s.insertErr
	}

	c.ID = uuid.New()
	s.inserts = append(s.inserts, c)

	return c, nil
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
	beginErr     error
	createErr    error
	createResult *pkwebauthn.Credential

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
		ID:              []byte{0xCA, 0xFE, 0xBA, 0xBE},
		PublicKey:       []byte{0xDE, 0xAD},
		AttestationType: "none",
	}, nil
}

// --- helpers ---

func newTestHandler(t *testing.T) (*AuthHandler, *fakeUserStore, *fakeCredentialStore, *fakeChallengeStore, *fakeWebAuthn) {
	t.Helper()

	users := newFakeUserStore()
	creds := &fakeCredentialStore{}
	chal := newFakeChallengeStore()
	wa := &fakeWebAuthn{}

	h := NewAuth(AuthDeps{
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		WebAuthn:    wa,
		Users:       users,
		Credentials: creds,
		Challenges:  chal,
	})

	return h, users, creds, chal, wa
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

	h, users, _, chal, wa := newTestHandler(t)

	rr := postJSON(h.BeginRegister, map[string]string{
		"username":     "alice",
		"display_name": "Alice",
	})
	c.Equal(http.StatusOK, rr.Code)

	// User row created.
	c.Len(users.users, 1)

	// Challenge session persisted.
	c.Len(chal.entries, 1)

	// WebAuthn called with the opaque handle, not the user UUID.
	c.NotNil(wa.lastBeginUser)
	c.Len(wa.lastBeginUser.Handle, pkwebauthn.UserHandleSize)
	c.Equal("alice", wa.lastBeginUser.Name)
}

func TestBeginRegister_InvalidJSON(t *testing.T) {
	c := require.New(t)

	h, _, _, _, _ := newTestHandler(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("not json")))
	h.BeginRegister(rr, req)

	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_request", decodeError(t, rr).Code)
}

func TestBeginRegister_MissingFields(t *testing.T) {
	c := require.New(t)

	h, _, _, _, _ := newTestHandler(t)

	rr := postJSON(h.BeginRegister, map[string]string{"username": "alice"})

	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("missing_fields", decodeError(t, rr).Code)
}

func TestBeginRegister_UsernameTaken(t *testing.T) {
	c := require.New(t)

	h, _, _, _, _ := newTestHandler(t)

	// First call succeeds.
	rr := postJSON(h.BeginRegister, map[string]string{"username": "bob", "display_name": "Bob"})
	c.Equal(http.StatusOK, rr.Code)

	// Second call with same username -> 409.
	rr = postJSON(h.BeginRegister, map[string]string{"username": "bob", "display_name": "Bob"})
	c.Equal(http.StatusConflict, rr.Code)
	c.Equal("username_taken", decodeError(t, rr).Code)
}

func TestBeginRegister_UserStoreError(t *testing.T) {
	c := require.New(t)

	h, users, _, _, _ := newTestHandler(t)
	users.nextErr = errors.New("db down")

	rr := postJSON(h.BeginRegister, map[string]string{"username": "carol", "display_name": "Carol"})

	c.Equal(http.StatusInternalServerError, rr.Code)
	c.Equal("internal_error", decodeError(t, rr).Code)
}

// --- CompleteRegister ---

func TestCompleteRegister_SessionNotFound(t *testing.T) {
	c := require.New(t)

	h, _, _, _, _ := newTestHandler(t)

	rr := postJSON(h.CompleteRegister, map[string]any{
		"session_id": "missing",
		"credential": json.RawMessage(`{}`),
	})

	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("session_invalid", decodeError(t, rr).Code)
}

func TestCompleteRegister_MissingFields(t *testing.T) {
	c := require.New(t)

	h, _, _, _, _ := newTestHandler(t)

	rr := postJSON(h.CompleteRegister, map[string]any{"session_id": ""})

	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("missing_fields", decodeError(t, rr).Code)
}

func TestCompleteRegister_InvalidJSON(t *testing.T) {
	c := require.New(t)

	h, _, _, _, _ := newTestHandler(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("not json")))
	h.CompleteRegister(rr, req)

	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_request", decodeError(t, rr).Code)
}

func TestCompleteRegister_SessionConsumedOnceOnly(t *testing.T) {
	c := require.New(t)

	h, _, _, chal, _ := newTestHandler(t)

	// Seed a stored registration session.
	userID := uuid.New()
	payload, err := json.Marshal(registrationSession{
		UserID:  userID,
		Session: pkwebauthn.SessionData{Challenge: "x", UserID: []byte("handle")},
	})
	c.NoError(err)
	c.NoError(chal.Save(context.Background(), "sess-x", payload))

	// We don't have a real credential JSON, so the first call will fail at
	// parse — but the important thing is that the challenge was consumed.
	rr := postJSON(h.CompleteRegister, map[string]any{
		"session_id": "sess-x",
		"credential": json.RawMessage(`{"id":"not real"}`),
	})
	c.NotEqual(http.StatusOK, rr.Code) // any non-2xx is fine here

	// Second attempt against the same session id must now report
	// session_invalid — replay protection.
	rr = postJSON(h.CompleteRegister, map[string]any{
		"session_id": "sess-x",
		"credential": json.RawMessage(`{}`),
	})
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("session_invalid", decodeError(t, rr).Code)
}
