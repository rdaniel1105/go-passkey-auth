package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
)

type fakeSessionStore struct {
	tokens map[string]uuid.UUID
	err    error
}

func (s *fakeSessionStore) Get(_ context.Context, token string) (uuid.UUID, error) {
	if s.err != nil {
		return uuid.Nil, s.err
	}

	id, ok := s.tokens[token]
	if !ok {
		return uuid.Nil, domain.ErrSessionNotFound
	}

	return id, nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// passthroughHandler reports the user id from context to the response body.
func passthroughHandler(c *require.Assertions, want uuid.UUID) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := UserIDFromContext(r.Context())
		c.True(ok, "user id missing from context")
		c.Equal(want, got)

		w.WriteHeader(http.StatusOK)
	})
}

func TestRequireSession_NoCookie(t *testing.T) {
	c := require.New(t)

	mw := RequireSession(&fakeSessionStore{}, quietLogger())
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler must not run")
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(rr, req)
	c.Equal(http.StatusUnauthorized, rr.Code)

	var body errorBody
	c.NoError(json.Unmarshal(rr.Body.Bytes(), &body))
	c.Equal("unauthorized", body.Code)
}

func TestRequireSession_EmptyCookieValue(t *testing.T) {
	c := require.New(t)

	mw := RequireSession(&fakeSessionStore{}, quietLogger())
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler must not run")
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: ""})

	handler.ServeHTTP(rr, req)
	c.Equal(http.StatusUnauthorized, rr.Code)
}

func TestRequireSession_UnknownToken(t *testing.T) {
	c := require.New(t)

	mw := RequireSession(&fakeSessionStore{tokens: map[string]uuid.UUID{}}, quietLogger())
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler must not run")
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "ghost"})

	handler.ServeHTTP(rr, req)
	c.Equal(http.StatusUnauthorized, rr.Code)
}

func TestRequireSession_ValidToken_InjectsUserID(t *testing.T) {
	c := require.New(t)

	userID := uuid.New()
	store := &fakeSessionStore{
		tokens: map[string]uuid.UUID{"tok-valid": userID},
	}

	mw := RequireSession(store, quietLogger())
	handler := mw(passthroughHandler(c, userID))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "tok-valid"})

	handler.ServeHTTP(rr, req)
	c.Equal(http.StatusOK, rr.Code)
}

func TestRequireSession_StoreError_5xx(t *testing.T) {
	c := require.New(t)

	store := &fakeSessionStore{err: errors.New("redis down")}

	mw := RequireSession(store, quietLogger())
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler must not run")
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "anything"})

	handler.ServeHTTP(rr, req)
	c.Equal(http.StatusInternalServerError, rr.Code)
}

func TestUserIDFromContext_AbsentWhenMiddlewareNotRun(t *testing.T) {
	c := require.New(t)

	_, ok := UserIDFromContext(context.Background())
	c.False(ok)
}
