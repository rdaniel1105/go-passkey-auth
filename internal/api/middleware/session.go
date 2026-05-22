// Package middleware holds the per-request adapters that wrap chi routes:
// authentication, structured request logging, and similar.
package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
)

// SessionCookieName is the name of the HttpOnly cookie carrying the opaque
// session token. The token is never returned in any JSON body; it lives
// only in this cookie. See PRD §13.
const SessionCookieName = "passkey_session"

// SessionStore is the slice of the session store the auth middleware needs.
type SessionStore interface {
	Get(ctx context.Context, token string) (uuid.UUID, error)
}

type contextKey struct{ name string }

var userIDContextKey = &contextKey{"user_id"}

// UserIDFromContext returns the user id injected by RequireSession, or
// (uuid.Nil, false) if the request didn't go through the middleware.
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDContextKey).(uuid.UUID)
	return id, ok
}

// RequireSession returns a middleware that:
//  1. Reads the session cookie.
//  2. Resolves it against the session store.
//  3. Injects the user id into the request context.
//
// Missing or invalid sessions get a 401 with a stable "unauthorized" code.
// Logger is required and used for store errors (never for the 401 path —
// missing/expired sessions are normal and not worth a log line).
func RequireSession(sessions SessionStore, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(SessionCookieName)
			if err != nil || cookie.Value == "" {
				writeUnauthorized(w)
				return
			}

			userID, err := sessions.Get(r.Context(), cookie.Value)
			if errors.Is(err, domain.ErrSessionNotFound) {
				writeUnauthorized(w)
				return
			}

			if err != nil {
				logger.Error("session lookup", "err", err)
				writeInternalError(w)
				return
			}

			ctx := context.WithValue(r.Context(), userIDContextKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(errorBody{
		Code:    "unauthorized",
		Message: "Authentication required.",
	})
}

func writeInternalError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(errorBody{
		Code:    "internal_error",
		Message: "Internal server error.",
	})
}
