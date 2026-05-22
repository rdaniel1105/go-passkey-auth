package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-passkey-auth/internal/api/middleware"
	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
)

type userHarness struct {
	handler *UserHandler
	users   *fakeUserStore
	creds   *fakeCredentialStore
}

func newUserHarness(t *testing.T) *userHarness {
	t.Helper()

	h := &userHarness{
		users: newFakeUserStore(),
		creds: newFakeCredentialStore(),
	}

	h.handler = NewUser(UserDeps{
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Users:       h.users,
		Credentials: h.creds,
	})

	return h
}

// reqWithUser builds an *http.Request whose context already has userID
// injected — simulating what RequireSession would have done upstream.
func reqWithUser(method, target string, userID uuid.UUID) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	ctx := contextWithUserID(req.Context(), userID)
	return req.WithContext(ctx)
}

// contextWithUserID is a tiny shim around middleware.UserIDFromContext's
// symmetric setter. The middleware package keeps the context key
// unexported, so we go through it for the test.
func contextWithUserID(ctx context.Context, userID uuid.UUID) context.Context {
	// We hit the actual middleware to inject; this proves the round-trip
	// works exactly as it will in production.
	store := &middlewareTestSessions{tokens: map[string]uuid.UUID{"t": userID}}

	out := ctx
	handler := middleware.RequireSession(store, slog.New(slog.NewTextHandler(io.Discard, nil)))(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			out = r.Context()
		}),
	)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: "t"})
	req = req.WithContext(ctx)
	handler.ServeHTTP(rr, req)

	return out
}

type middlewareTestSessions struct {
	tokens map[string]uuid.UUID
}

func (s *middlewareTestSessions) Get(_ context.Context, token string) (uuid.UUID, error) {
	id, ok := s.tokens[token]
	if !ok {
		return uuid.Nil, domain.ErrSessionNotFound
	}

	return id, nil
}

// --- Me ---

func TestMe_HappyPath(t *testing.T) {
	c := require.New(t)

	h := newUserHarness(t)

	user, err := h.users.CreateRegistered(context.Background(), "alice", "Alice")
	c.NoError(err)

	rr := httptest.NewRecorder()
	req := reqWithUser(http.MethodGet, "/", user.ID)

	h.handler.Me(rr, req)
	c.Equal(http.StatusOK, rr.Code)

	var body meResponse
	c.NoError(json.Unmarshal(rr.Body.Bytes(), &body))
	c.Equal(user.ID.String(), body.UserID)
	c.Equal("alice", body.Username)
	c.Equal("Alice", body.DisplayName)
	c.False(body.IsGuest)
}

func TestMe_NoSessionInContext(t *testing.T) {
	c := require.New(t)

	h := newUserHarness(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h.handler.Me(rr, req)
	c.Equal(http.StatusUnauthorized, rr.Code)
}

func TestMe_UserDeleted(t *testing.T) {
	c := require.New(t)

	h := newUserHarness(t)

	rr := httptest.NewRecorder()
	req := reqWithUser(http.MethodGet, "/", uuid.New())

	h.handler.Me(rr, req)
	c.Equal(http.StatusUnauthorized, rr.Code)
}

// --- ListCredentials ---

func TestListCredentials_HappyPath(t *testing.T) {
	c := require.New(t)

	h := newUserHarness(t)

	user, err := h.users.CreateRegistered(context.Background(), "bob", "Bob")
	c.NoError(err)

	for _, b := range []byte{0x01, 0x02} {
		_, err := h.creds.Insert(context.Background(), &domain.Credential{
			UserID:            user.ID,
			CredentialID:      []byte{b},
			PublicKey:         []byte{b},
			AttestationFormat: "none",
			AttestationType:   "none",
		})
		c.NoError(err)
	}

	rr := httptest.NewRecorder()
	req := reqWithUser(http.MethodGet, "/", user.ID)

	h.handler.ListCredentials(rr, req)
	c.Equal(http.StatusOK, rr.Code)

	var body []credentialResponse
	c.NoError(json.Unmarshal(rr.Body.Bytes(), &body))
	c.Len(body, 2)
}

func TestListCredentials_EmptyList(t *testing.T) {
	c := require.New(t)

	h := newUserHarness(t)

	user, err := h.users.CreateRegistered(context.Background(), "carol", "Carol")
	c.NoError(err)

	rr := httptest.NewRecorder()
	req := reqWithUser(http.MethodGet, "/", user.ID)

	h.handler.ListCredentials(rr, req)
	c.Equal(http.StatusOK, rr.Code)
	c.Equal("[]\n", rr.Body.String())
}

// --- DeleteCredential ---

// routeWithID exercises the chi URL param wiring so chi.URLParam returns
// the value the handler expects.
func routeWithID(handler http.HandlerFunc) http.Handler {
	r := chi.NewRouter()
	r.Delete("/credentials/{id}", handler)
	return r
}

func TestDeleteCredential_InvalidUUID(t *testing.T) {
	c := require.New(t)

	h := newUserHarness(t)

	rr := httptest.NewRecorder()
	req := reqWithUser(http.MethodDelete, "/credentials/not-a-uuid", uuid.New())

	routeWithID(h.handler.DeleteCredential).ServeHTTP(rr, req)
	c.Equal(http.StatusBadRequest, rr.Code)
}

func TestDeleteCredential_NotOwned(t *testing.T) {
	c := require.New(t)

	h := newUserHarness(t)

	owner, err := h.users.CreateRegistered(context.Background(), "owner", "Owner")
	c.NoError(err)

	cred, err := h.creds.Insert(context.Background(), &domain.Credential{
		UserID:            owner.ID,
		CredentialID:      []byte{0x10},
		PublicKey:         []byte{0x10},
		AttestationFormat: "none",
		AttestationType:   "none",
	})
	c.NoError(err)

	other, err := h.users.CreateRegistered(context.Background(), "other", "Other")
	c.NoError(err)

	rr := httptest.NewRecorder()
	req := reqWithUser(http.MethodDelete, "/credentials/"+cred.ID.String(), other.ID)

	routeWithID(h.handler.DeleteCredential).ServeHTTP(rr, req)
	c.Equal(http.StatusNotFound, rr.Code)
}

func TestDeleteCredential_OwnedAndDeleted(t *testing.T) {
	c := require.New(t)

	h := newUserHarness(t)
	// Override the fake's SoftDelete behavior for this test.
	h.creds.softDeleteOverride = func(id uuid.UUID) error { return nil }

	user, err := h.users.CreateRegistered(context.Background(), "del", "Del")
	c.NoError(err)

	cred, err := h.creds.Insert(context.Background(), &domain.Credential{
		UserID:            user.ID,
		CredentialID:      []byte{0x20},
		PublicKey:         []byte{0x20},
		AttestationFormat: "none",
		AttestationType:   "none",
	})
	c.NoError(err)

	rr := httptest.NewRecorder()
	req := reqWithUser(http.MethodDelete, "/credentials/"+cred.ID.String(), user.ID)

	routeWithID(h.handler.DeleteCredential).ServeHTTP(rr, req)
	c.Equal(http.StatusNoContent, rr.Code)
}

func TestDeleteCredential_LastCredentialGuard(t *testing.T) {
	c := require.New(t)

	h := newUserHarness(t)
	h.creds.softDeleteOverride = func(_ uuid.UUID) error { return domain.ErrLastCredential }

	user, err := h.users.CreateRegistered(context.Background(), "solo", "Solo")
	c.NoError(err)

	cred, err := h.creds.Insert(context.Background(), &domain.Credential{
		UserID:            user.ID,
		CredentialID:      []byte{0x30},
		PublicKey:         []byte{0x30},
		AttestationFormat: "none",
		AttestationType:   "none",
	})
	c.NoError(err)

	rr := httptest.NewRecorder()
	req := reqWithUser(http.MethodDelete, "/credentials/"+cred.ID.String(), user.ID)

	routeWithID(h.handler.DeleteCredential).ServeHTTP(rr, req)
	c.Equal(http.StatusConflict, rr.Code)

	var body errorBody
	c.NoError(json.Unmarshal(rr.Body.Bytes(), &body))
	c.Equal("last_credential", body.Code)
}
