package middleware

import (
	"log/slog"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// RequestLogger returns a middleware that emits one structured log line
// per request, after the inner handler has run. It pairs with chi's
// middleware.RequestID upstream — the request id is pulled from context
// and included in every line so logs can be correlated.
//
// Health endpoints are typically high-volume and uninteresting; the
// returned middleware skips logging when the path matches /health or
// /health/ready.
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skipLogging(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
				"remote_ip", r.RemoteAddr,
				"request_id", chimw.GetReqID(r.Context()),
			}

			if userID, ok := UserIDFromContext(r.Context()); ok {
				attrs = append(attrs, "user_id", userID.String())
			}

			level := slog.LevelInfo
			switch {
			case ww.Status() >= 500:
				level = slog.LevelError
			case ww.Status() >= 400:
				level = slog.LevelWarn
			}

			logger.LogAttrs(r.Context(), level, "http request", toAttrs(attrs)...)
		})
	}
}

func skipLogging(path string) bool {
	return path == "/health" || path == "/health/ready"
}

func toAttrs(kv []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		key, _ := kv[i].(string)
		out = append(out, slog.Any(key, kv[i+1]))
	}

	return out
}
