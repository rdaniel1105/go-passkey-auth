package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// captureLogger returns a slog.Logger that writes JSON lines to buf so
// individual log lines can be parsed by tests.
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// runWithLogger sends a single request through the logger middleware and
// returns the captured JSON object. chi.RequestID is wired upstream so
// the request_id attribute is non-empty.
func runWithLogger(t *testing.T, path string, status int) map[string]any {
	t.Helper()

	c := require.New(t)

	var buf bytes.Buffer
	logger := captureLogger(&buf)

	stack := chimw.RequestID(RequestLogger(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("ok"))
	})))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	stack.ServeHTTP(rr, req)

	if buf.Len() == 0 {
		return nil
	}

	var entry map[string]any
	c.NoError(json.Unmarshal(buf.Bytes(), &entry))
	return entry
}

func TestRequestLogger_LogsSuccessAtInfo(t *testing.T) {
	c := require.New(t)

	entry := runWithLogger(t, "/api/v1/auth/register/begin", http.StatusOK)
	c.NotNil(entry)
	c.Equal("INFO", entry["level"])
	c.Equal("http request", entry["msg"])
	c.Equal("GET", entry["method"])
	c.Equal("/api/v1/auth/register/begin", entry["path"])
	c.Equal(float64(http.StatusOK), entry["status"])
	c.NotEmpty(entry["request_id"])
}

func TestRequestLogger_4xxLogsAtWarn(t *testing.T) {
	c := require.New(t)

	entry := runWithLogger(t, "/api/v1/auth/login/complete", http.StatusBadRequest)
	c.Equal("WARN", entry["level"])
	c.Equal(float64(http.StatusBadRequest), entry["status"])
}

func TestRequestLogger_5xxLogsAtError(t *testing.T) {
	c := require.New(t)

	entry := runWithLogger(t, "/api/v1/auth/login/complete", http.StatusInternalServerError)
	c.Equal("ERROR", entry["level"])
	c.Equal(float64(http.StatusInternalServerError), entry["status"])
}

func TestRequestLogger_SkipsHealth(t *testing.T) {
	c := require.New(t)

	for _, path := range []string{"/health", "/health/ready"} {
		entry := runWithLogger(t, path, http.StatusOK)
		c.Nil(entry, "expected no log for %q, got %v", path, entry)
	}
}

func TestRequestLogger_IncludesUserIDWhenInContext(t *testing.T) {
	c := require.New(t)

	var buf bytes.Buffer
	logger := captureLogger(&buf)

	userID := uuid.New()

	// Simulate RequireSession having run upstream — inject user id into
	// context via the middleware's own path so we don't reach into private
	// API just to test logging.
	stack := chimw.RequestID(injectUser(userID)(RequestLogger(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	stack.ServeHTTP(rr, req)

	var entry map[string]any
	c.NoError(json.Unmarshal(buf.Bytes(), &entry))
	c.Equal(userID.String(), entry["user_id"])
}

// injectUser is a test-only middleware that puts a user id in context,
// mimicking what RequireSession does without needing a session store.
func injectUser(id uuid.UUID) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := contextWithUserIDForTest(r.Context(), id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
