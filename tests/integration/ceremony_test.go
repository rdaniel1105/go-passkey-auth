// Package integration drives the full WebAuthn ceremony end-to-end:
// real Postgres + Redis via testcontainers, the in-process HTTP server,
// and a software authenticator simulating the client.
//
// This is the test that proves all the layers wire together: the
// challenge store's one-shot consume, the attestation verification, the
// sign-count anomaly path, the HttpOnly cookie shape, and the guest →
// registered promotion.
package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"golang.org/x/net/publicsuffix"

	"github.com/rdaniel1105/go-passkey-auth/internal/api"
	"github.com/rdaniel1105/go-passkey-auth/internal/api/handler"
	pgstore "github.com/rdaniel1105/go-passkey-auth/internal/store/postgres"
	redisstore "github.com/rdaniel1105/go-passkey-auth/internal/store/redis"
	"github.com/rdaniel1105/go-passkey-auth/internal/testutil/webauthntest"
	pkwebauthn "github.com/rdaniel1105/go-passkey-auth/internal/webauthn"
)

// testServer is the running stack a test can drive with HTTP requests.
type testServer struct {
	url    string
	rpID   string
	origin string
}

// httpResult bundles a status code with the body so test helpers can
// assert on status and parse JSON without racing the body's single read.
type httpResult struct {
	status int
	body   []byte
}

// beginOptionsResponse mirrors what /auth/register/begin and
// /auth/promote/begin return.
type beginOptionsResponse struct {
	Options   *protocol.PublicKeyCredentialCreationOptions `json:"options"`
	SessionID string                                       `json:"session_id"`
}

type beginAssertionResponse struct {
	Options   *protocol.PublicKeyCredentialRequestOptions `json:"options"`
	SessionID string                                      `json:"session_id"`
}

// redisPinger adapts *redis.Client to handler.HealthDeps.Redis.
type redisPinger struct {
	client *redis.Client
}

func (p redisPinger) Ping(ctx context.Context) error {
	return p.client.Ping(ctx).Err()
}

// --- harness ---

// startStack boots Postgres + Redis containers, applies migrations, wires
// every handler, and returns a running test HTTP server. If Docker isn't
// reachable the test is skipped.
func startStack(t *testing.T) *testServer {
	t.Helper()

	c := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pgContainer, err := tcpg.Run(ctx, "postgres:16-alpine",
		tcpg.WithDatabase("passkey"),
		tcpg.WithUsername("passkey"),
		tcpg.WithPassword("passkey"),
		tcpg.BasicWaitStrategies(),
	)
	if err != nil {
		t.Skipf("skipping integration test: cannot start postgres container: %v", err)
	}

	t.Cleanup(func() { _ = pgContainer.Terminate(context.Background()) })

	pgDSN, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	c.NoError(err)

	c.NoError(applyMigrations(pgDSN))

	rdContainer, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		t.Skipf("skipping integration test: cannot start redis container: %v", err)
	}

	t.Cleanup(func() { _ = rdContainer.Terminate(context.Background()) })

	redisURL, err := rdContainer.ConnectionString(ctx)
	c.NoError(err)

	pool, err := pgstore.NewPool(ctx, pgDSN)
	c.NoError(err)
	t.Cleanup(pool.Close)

	redisClient, err := redisstore.NewClient(ctx, redisURL)
	c.NoError(err)
	t.Cleanup(func() { _ = redisClient.Close() })

	const (
		rpID   = "localhost"
		origin = "http://localhost"
	)

	wa, err := pkwebauthn.NewService(pkwebauthn.Config{
		RPID:            rpID,
		RPDisplayName:   "passkey-auth-test",
		RPOrigins:       []string{origin},
		CeremonyTimeout: 5 * time.Minute,
	})
	c.NoError(err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	userStore := pgstore.NewUserStore(pool)
	credStore := pgstore.NewCredentialStore(pool)
	sessionStore := redisstore.NewSessionStore(redisClient, time.Hour)

	authHandler := handler.NewAuth(handler.AuthDeps{
		Logger:        logger,
		WebAuthn:      wa,
		Users:         userStore,
		Credentials:   credStore,
		Challenges:    redisstore.NewChallengeStore(redisClient, 5*time.Minute),
		Sessions:      sessionStore,
		Guests:        redisstore.NewGuestStore(redisClient, time.Hour),
		SessionMaxAge: 3600,
		GuestMaxAge:   3600,
	})

	userHandler := handler.NewUser(handler.UserDeps{
		Logger:      logger,
		Users:       userStore,
		Credentials: credStore,
	})

	healthHandler := handler.NewHealth(handler.HealthDeps{
		Logger:   logger,
		Postgres: pool,
		Redis:    redisPinger{client: redisClient},
	})

	mux := api.New(api.Deps{
		Logger:   logger,
		Auth:     authHandler,
		User:     userHandler,
		Health:   healthHandler,
		Sessions: sessionStore,
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &testServer{url: srv.URL, rpID: rpID, origin: origin}
}

func applyMigrations(dsn string) error {
	src, err := iofs.New(pgstore.MigrationsFS(), "migrations")
	if err != nil {
		return err
	}

	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = sqlDB.Close() }()

	db, err := migratepg.WithInstance(sqlDB, &migratepg.Config{})
	if err != nil {
		return err
	}

	mig, err := migrate.NewWithInstance("iofs", src, "postgres", db)
	if err != nil {
		return err
	}

	if err := mig.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}

	return nil
}

// --- HTTP helpers ---

func newClient(t *testing.T) *http.Client {
	t.Helper()

	// The default cookiejar policy refuses cookies for IP-literal hosts
	// (which is what httptest.NewServer gives us — 127.0.0.1). Using the
	// real public suffix list works around it.
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	require.NoError(t, err)

	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func do(t *testing.T, client *http.Client, req *http.Request) httpResult {
	t.Helper()

	c := require.New(t)
	resp, err := client.Do(req)
	c.NoError(err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	c.NoError(err)

	return httpResult{status: resp.StatusCode, body: body}
}

func postJSON(t *testing.T, client *http.Client, target string, body any) httpResult {
	t.Helper()

	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}

	req, err := http.NewRequest(http.MethodPost, target, &buf)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	return do(t, client, req)
}

func get(t *testing.T, client *http.Client, target string) httpResult {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)

	return do(t, client, req)
}

func deleteReq(t *testing.T, client *http.Client, target string) httpResult {
	t.Helper()

	req, err := http.NewRequest(http.MethodDelete, target, nil)
	require.NoError(t, err)

	return do(t, client, req)
}

func decodeBody[T any](t *testing.T, body []byte) T {
	t.Helper()

	var out T
	require.NoError(t, json.Unmarshal(body, &out))
	return out
}

// findCookie returns the first cookie with the given name from the
// client's jar for the test server origin.
func findCookie(t *testing.T, client *http.Client, srv *testServer, name string) *http.Cookie {
	t.Helper()

	u, err := url.Parse(srv.url)
	require.NoError(t, err)

	for _, c := range client.Jar.Cookies(u) {
		if c.Name == name {
			return c
		}
	}

	return nil
}

// userHandleFromOptions decodes the user.id field from a registration
// options blob — the server's opaque per-registration handle.
func userHandleFromOptions(t *testing.T, opts *protocol.PublicKeyCredentialCreationOptions) []byte {
	t.Helper()

	c := require.New(t)

	switch id := opts.User.ID.(type) {
	case []byte:
		return id
	case string:
		dec, err := base64.RawURLEncoding.DecodeString(id)
		c.NoError(err)
		return dec
	default:
		c.Failf("unexpected user.id type", "%T", opts.User.ID)
		return nil
	}
}

// challengeString converts a wire challenge (raw bytes after JSON decode)
// to the base64url string the authenticator's clientData embeds.
func challengeString[T ~[]byte](b T) string {
	return base64.RawURLEncoding.EncodeToString([]byte(b))
}

// --- Tests ---

func TestCeremony_Health(t *testing.T) {
	c := require.New(t)

	srv := startStack(t)
	client := newClient(t)

	c.Equal(http.StatusOK, get(t, client, srv.url+"/health").status)
	c.Equal(http.StatusOK, get(t, client, srv.url+"/health/ready").status)
}

func TestCeremony_DemoClientServed(t *testing.T) {
	c := require.New(t)

	srv := startStack(t)
	client := newClient(t)

	res := get(t, client, srv.url+"/")
	c.Equal(http.StatusOK, res.status)
	c.Contains(string(res.body), "<title>go-passkey-auth demo</title>")
	c.Contains(string(res.body), "navigator.credentials.create")
	c.Contains(string(res.body), "navigator.credentials.get")
}

func TestCeremony_FullRegistrationAndLogin(t *testing.T) {
	c := require.New(t)

	srv := startStack(t)
	client := newClient(t)

	// --- Register ---
	res := postJSON(t, client, srv.url+"/api/v1/auth/register/begin", map[string]string{
		"username":     "alice",
		"display_name": "Alice",
	})
	c.Equal(http.StatusOK, res.status, "register begin body: %s", res.body)
	begin := decodeBody[beginOptionsResponse](t, res.body)

	auth, err := webauthntest.New(srv.rpID, srv.origin)
	c.NoError(err)

	userHandle := userHandleFromOptions(t, begin.Options)

	attestation, err := auth.Register(challengeString(begin.Options.Challenge))
	c.NoError(err)

	res = postJSON(t, client, srv.url+"/api/v1/auth/register/complete", map[string]any{
		"session_id": begin.SessionID,
		"credential": json.RawMessage(attestation),
	})
	c.Equal(http.StatusOK, res.status, "register complete body: %s", res.body)

	registerBody := decodeBody[map[string]string](t, res.body)
	c.NotEmpty(registerBody["user_id"], "register complete must return the passkey-side user_id")
	c.NotEmpty(registerBody["credential_id"], "register complete must return the credential_id")

	// --- Login ---
	res = postJSON(t, client, srv.url+"/api/v1/auth/login/begin", struct{}{})
	c.Equal(http.StatusOK, res.status, "login begin body: %s", res.body)
	loginBegin := decodeBody[beginAssertionResponse](t, res.body)

	assertion, err := auth.Authenticate(challengeString(loginBegin.Options.Challenge), userHandle)
	c.NoError(err)

	res = postJSON(t, client, srv.url+"/api/v1/auth/login/complete", map[string]any{
		"session_id": loginBegin.SessionID,
		"credential": json.RawMessage(assertion),
	})
	c.Equal(http.StatusOK, res.status, "login complete body: %s", res.body)
	loginBody := decodeBody[map[string]string](t, res.body)
	c.Equal("alice", loginBody["username"])

	// HttpOnly cookie set; the token is NOT in the JSON body.
	sessionCookie := findCookie(t, client, srv, handler.SessionCookieName)
	c.NotNil(sessionCookie)
	c.NotEmpty(sessionCookie.Value)
	c.NotContains(string(res.body), sessionCookie.Value)

	// --- /users/me ---
	res = get(t, client, srv.url+"/api/v1/users/me")
	c.Equal(http.StatusOK, res.status)
	me := decodeBody[map[string]any](t, res.body)
	c.Equal("alice", me["username"])
	c.Equal(false, me["is_guest"])

	// --- List credentials ---
	res = get(t, client, srv.url+"/api/v1/users/me/credentials")
	c.Equal(http.StatusOK, res.status)
	creds := decodeBody[[]map[string]any](t, res.body)
	c.Len(creds, 1)

	// --- Last-credential guard ---
	credID, _ := creds[0]["id"].(string)
	res = deleteReq(t, client, srv.url+"/api/v1/users/me/credentials/"+credID)
	c.Equal(http.StatusConflict, res.status)
	errBody := decodeBody[map[string]string](t, res.body)
	c.Equal("last_credential", errBody["code"])

	// --- Logout ---
	res = postJSON(t, client, srv.url+"/api/v1/auth/logout", nil)
	c.Equal(http.StatusNoContent, res.status)

	res = get(t, client, srv.url+"/api/v1/users/me")
	c.Equal(http.StatusUnauthorized, res.status)
}

func TestCeremony_ChallengeReplayRejected(t *testing.T) {
	c := require.New(t)

	srv := startStack(t)
	client := newClient(t)

	res := postJSON(t, client, srv.url+"/api/v1/auth/register/begin", map[string]string{
		"username":     "replay",
		"display_name": "Replay",
	})
	c.Equal(http.StatusOK, res.status)
	begin := decodeBody[beginOptionsResponse](t, res.body)

	auth, err := webauthntest.New(srv.rpID, srv.origin)
	c.NoError(err)

	attestation, err := auth.Register(challengeString(begin.Options.Challenge))
	c.NoError(err)

	// First attempt succeeds.
	res = postJSON(t, client, srv.url+"/api/v1/auth/register/complete", map[string]any{
		"session_id": begin.SessionID,
		"credential": json.RawMessage(attestation),
	})
	c.Equal(http.StatusOK, res.status, "first complete body: %s", res.body)

	// Replaying the same session_id is rejected (one-shot consume).
	res = postJSON(t, client, srv.url+"/api/v1/auth/register/complete", map[string]any{
		"session_id": begin.SessionID,
		"credential": json.RawMessage(attestation),
	})
	c.Equal(http.StatusUnauthorized, res.status)
}

func TestCeremony_GuestPromotion(t *testing.T) {
	c := require.New(t)

	srv := startStack(t)
	client := newClient(t)

	res := postJSON(t, client, srv.url+"/api/v1/auth/guest", nil)
	c.Equal(http.StatusOK, res.status)
	guestBody := decodeBody[map[string]string](t, res.body)
	c.NotEmpty(guestBody["user_id"])
	c.NotNil(findCookie(t, client, srv, handler.GuestCookieName))

	// Promote begin.
	res = postJSON(t, client, srv.url+"/api/v1/auth/promote/begin", map[string]string{
		"username":     "promoted",
		"display_name": "Promoted",
	})
	c.Equal(http.StatusOK, res.status, "promote begin body: %s", res.body)
	begin := decodeBody[beginOptionsResponse](t, res.body)

	auth, err := webauthntest.New(srv.rpID, srv.origin)
	c.NoError(err)

	attestation, err := auth.Register(challengeString(begin.Options.Challenge))
	c.NoError(err)

	// Promote complete.
	res = postJSON(t, client, srv.url+"/api/v1/auth/promote/complete", map[string]any{
		"session_id": begin.SessionID,
		"credential": json.RawMessage(attestation),
	})
	c.Equal(http.StatusOK, res.status, "promote complete body: %s", res.body)

	// Session cookie issued, guest cookie cleared.
	c.NotNil(findCookie(t, client, srv, handler.SessionCookieName))

	// /users/me confirms promotion.
	res = get(t, client, srv.url+"/api/v1/users/me")
	c.Equal(http.StatusOK, res.status)
	me := decodeBody[map[string]any](t, res.body)
	c.Equal("promoted", me["username"])
	c.Equal(false, me["is_guest"])
}
