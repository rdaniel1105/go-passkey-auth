package handler

import (
	"net/http"

	"github.com/rdaniel1105/go-passkey-auth/internal/api/middleware"
)

// SessionCookieName is re-exported here so handler tests can reference it
// without importing middleware just for the constant.
const SessionCookieName = middleware.SessionCookieName

// setSessionCookie writes the session cookie with the security flags PRD
// §13 calls for. Secure is on when the request looks like HTTPS so the
// cookie is rejected over plain HTTP in prod; local http://localhost dev
// still works because browsers exempt it.
func setSessionCookie(w http.ResponseWriter, r *http.Request, token string, maxAgeSeconds int) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAgeSeconds,
	})
}

// clearSessionCookie writes an expired session cookie to invalidate any
// existing one on the client.
func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// isHTTPS reports whether the request looks like it came in over TLS,
// honouring X-Forwarded-Proto for reverse-proxied deployments.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}

	return r.Header.Get("X-Forwarded-Proto") == "https"
}
