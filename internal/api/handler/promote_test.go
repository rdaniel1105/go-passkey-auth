package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
	pkwebauthn "github.com/rdaniel1105/go-passkey-auth/internal/webauthn"
)

// --- Guest ---

func TestGuest_CreatesNewUserAndCookie(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	rr := postJSON(h.handler.Guest, struct{}{})
	c.Equal(http.StatusOK, rr.Code)

	c.Len(h.users.users, 1)
	for _, u := range h.users.users {
		c.True(u.IsGuest)
	}

	c.Len(h.guests.created, 1)

	var cookie *http.Cookie
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == GuestCookieName {
			cookie = ck
		}
	}
	c.NotNil(cookie)
	c.True(cookie.HttpOnly)
	c.Equal(h.guests.created[0], cookie.Value)
}

func TestGuest_ReusesExistingCookie(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	// First call: makes a guest.
	rr := postJSON(h.handler.Guest, struct{}{})
	c.Equal(http.StatusOK, rr.Code)
	firstToken := rr.Result().Cookies()[0].Value

	// Second call presenting the same cookie: must not create another user
	// or token.
	rr2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: GuestCookieName, Value: firstToken})
	h.handler.Guest(rr2, req)

	c.Equal(http.StatusOK, rr2.Code)
	c.Len(h.users.users, 1, "must not create a second guest user")
	c.Len(h.guests.created, 1, "must not mint a second guest token")
}

// --- BeginPromote ---

func TestBeginPromote_NoGuestCookie(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	rr := postJSON(h.handler.BeginPromote, map[string]string{"username": "alice", "display_name": "Alice"})
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("guest_invalid", decodeError(t, rr).Code)
}

func TestBeginPromote_MissingFields(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	// Need a guest cookie present, but fields missing should still 400.
	guestID := uuid.New()
	h.users.users[guestID] = &domain.User{ID: guestID, IsGuest: true, Username: "guest", DisplayName: "Guest"}
	token, _ := h.guests.Create(context.Background(), guestID)

	rr := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"username": "alice"})
	req := httptest.NewRequest(http.MethodPost, "/", bytesReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: GuestCookieName, Value: token})
	h.handler.BeginPromote(rr, req)

	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("missing_fields", decodeError(t, rr).Code)
}

func TestBeginPromote_NotAGuest(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	// User exists but is_guest = false — guest cookie should not work.
	registered, err := h.users.CreateRegistered(context.Background(), "registered", "R")
	c.NoError(err)
	token, _ := h.guests.Create(context.Background(), registered.ID)

	rr := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"username": "x", "display_name": "X"})
	req := httptest.NewRequest(http.MethodPost, "/", bytesReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: GuestCookieName, Value: token})
	h.handler.BeginPromote(rr, req)

	c.Equal(http.StatusConflict, rr.Code)
	c.Equal("not_a_guest", decodeError(t, rr).Code)
}

func TestBeginPromote_HappyPath(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	guest, err := h.users.CreateGuest(context.Background(), "guest-xyz", "Guest")
	c.NoError(err)
	token, _ := h.guests.Create(context.Background(), guest.ID)

	rr := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"username": "alice", "display_name": "Alice"})
	req := httptest.NewRequest(http.MethodPost, "/", bytesReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: GuestCookieName, Value: token})
	h.handler.BeginPromote(rr, req)

	c.Equal(http.StatusOK, rr.Code)
	c.Len(h.chal.entries, 1)

	// The stored session must carry Promote = true and the chosen name.
	var stored registrationSession
	for _, payload := range h.chal.entries {
		c.NoError(json.Unmarshal(payload, &stored))
	}
	c.True(stored.Promote)
	c.Equal("alice", stored.PromoteName)
	c.Equal("Alice", stored.PromoteDisplay)
	c.Equal(guest.ID, stored.UserID)
}

// --- CompletePromote ---

func TestCompletePromote_HappyPath(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	guest, err := h.users.CreateGuest(context.Background(), "guest-cp", "Guest")
	c.NoError(err)
	guestTok, _ := h.guests.Create(context.Background(), guest.ID)

	payload, err := json.Marshal(registrationSession{
		UserID:         guest.ID,
		Session:        pkwebauthn.SessionData{UserID: []byte("handle")},
		Promote:        true,
		PromoteName:    "alice",
		PromoteDisplay: "Alice",
	})
	c.NoError(err)
	c.NoError(h.chal.Save(context.Background(), "sess-p", payload))

	h.wa.createResult = &pkwebauthn.Credential{
		ID:                []byte{0xAA},
		PublicKey:         []byte{0xBB},
		AttestationFormat: "none",
		AttestationType:   "none",
	}

	rr := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"session_id": "sess-p",
		"credential": json.RawMessage(`{"id":"x"}`),
	})
	req := httptest.NewRequest(http.MethodPost, "/", bytesReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: GuestCookieName, Value: guestTok})
	h.handler.CompletePromote(rr, req)

	c.Equal(http.StatusOK, rr.Code)

	// User row promoted.
	c.False(h.users.users[guest.ID].IsGuest)
	c.Equal("alice", h.users.users[guest.ID].Username)
	c.NotNil(h.users.users[guest.ID].PromotedAt)

	// Credential inserted.
	c.Len(h.creds.inserts, 1)

	// Session cookie issued.
	var sessionCookie, guestCookie *http.Cookie
	for _, ck := range rr.Result().Cookies() {
		switch ck.Name {
		case SessionCookieName:
			sessionCookie = ck
		case GuestCookieName:
			guestCookie = ck
		}
	}
	c.NotNil(sessionCookie)
	c.NotEmpty(sessionCookie.Value)
	c.True(sessionCookie.HttpOnly)

	// Guest cookie cleared.
	c.NotNil(guestCookie)
	c.True(guestCookie.MaxAge < 0, "guest cookie not expired")

	// Guest token deleted from store.
	c.Equal([]string{guestTok}, h.guests.deleted)
}

func TestCompletePromote_RefusesNonPromoteSession(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	// Session was minted as a regular register, not a promote.
	payload, err := json.Marshal(registrationSession{
		UserID:  uuid.New(),
		Session: pkwebauthn.SessionData{UserID: []byte("handle")},
	})
	c.NoError(err)
	c.NoError(h.chal.Save(context.Background(), "sess-r", payload))

	rr := postJSON(h.handler.CompletePromote, map[string]any{
		"session_id": "sess-r",
		"credential": json.RawMessage(`{"id":"x"}`),
	})

	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("session_invalid", decodeError(t, rr).Code)
}

func TestCompleteRegister_RefusesPromoteSession(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	// Symmetric guard: /register/complete must reject a promote session.
	payload, err := json.Marshal(registrationSession{
		UserID:  uuid.New(),
		Session: pkwebauthn.SessionData{UserID: []byte("handle")},
		Promote: true,
	})
	c.NoError(err)
	c.NoError(h.chal.Save(context.Background(), "sess-cross", payload))

	rr := postJSON(h.handler.CompleteRegister, map[string]any{
		"session_id": "sess-cross",
		"credential": json.RawMessage(`{"id":"x"}`),
	})

	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("session_invalid", decodeError(t, rr).Code)
}

func TestCompletePromote_UsernameTaken(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	// Pre-claim the username with a different registered user.
	_, err := h.users.CreateRegistered(context.Background(), "alice", "Alice")
	c.NoError(err)

	guest, err := h.users.CreateGuest(context.Background(), "guest-conflict", "Guest")
	c.NoError(err)
	guestTok, _ := h.guests.Create(context.Background(), guest.ID)

	payload, err := json.Marshal(registrationSession{
		UserID:         guest.ID,
		Session:        pkwebauthn.SessionData{UserID: []byte("handle")},
		Promote:        true,
		PromoteName:    "alice",
		PromoteDisplay: "Alice",
	})
	c.NoError(err)
	c.NoError(h.chal.Save(context.Background(), "sess-conflict", payload))

	h.wa.createResult = &pkwebauthn.Credential{
		ID:                []byte{0xAB},
		PublicKey:         []byte{0xCD},
		AttestationFormat: "none",
		AttestationType:   "none",
	}

	rr := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"session_id": "sess-conflict",
		"credential": json.RawMessage(`{"id":"x"}`),
	})
	req := httptest.NewRequest(http.MethodPost, "/", bytesReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: GuestCookieName, Value: guestTok})
	h.handler.CompletePromote(rr, req)

	c.Equal(http.StatusConflict, rr.Code)
	c.Equal("username_taken", decodeError(t, rr).Code)

	// User must still be a guest — failed promotion is rollback at user level.
	c.True(h.users.users[guest.ID].IsGuest)

	// No credential inserted.
	c.Empty(h.creds.inserts)
}

// --- Login complete with guest cookie present ---

func TestCompleteLogin_ClearsGuestCookieOnSuccess(t *testing.T) {
	c := require.New(t)

	h := newTestHandler(t)

	userID := uuid.New()
	credentialID := []byte{0xFA, 0xCE}
	seedLogin(t, h, "sess-merge", userID, credentialID, 1)

	// Independently created guest session belonging to (a different) anon user.
	anonID := uuid.New()
	h.users.users[anonID] = &domain.User{ID: anonID, IsGuest: true, Username: "anon", DisplayName: "Anon"}
	guestTok, _ := h.guests.Create(context.Background(), anonID)

	h.wa.validateResult = &pkwebauthn.Credential{
		ID: credentialID,
		Authenticator: pkwebauthn.Authenticator{
			SignCount: 2,
		},
	}

	rr := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"session_id": "sess-merge",
		"credential": credentialJSON(credentialID),
	})
	req := httptest.NewRequest(http.MethodPost, "/", bytesReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: GuestCookieName, Value: guestTok})
	h.handler.CompleteLogin(rr, req)

	c.Equal(http.StatusOK, rr.Code)

	// Guest token deleted.
	c.Contains(h.guests.deleted, guestTok)

	// Guest cookie expired on the wire.
	var guestCookie *http.Cookie
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == GuestCookieName {
			guestCookie = ck
		}
	}
	c.NotNil(guestCookie)
	c.True(guestCookie.MaxAge < 0)
}

// --- helpers ---

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
