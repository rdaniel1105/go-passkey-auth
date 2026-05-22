package handler

import "net/http"

// SessionCookieName is the name of the HttpOnly cookie that carries the
// opaque session token. PRD §13: the token is never returned in the JSON
// body — only in this cookie.
const SessionCookieName = "passkey_session"

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
