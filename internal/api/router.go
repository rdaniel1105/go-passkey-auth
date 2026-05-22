// Package api wires HTTP handlers to a chi router. The router builder is
// the single place where the URL surface is declared; handlers themselves
// know nothing about routing.
package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/rdaniel1105/go-passkey-auth/internal/api/handler"
	"github.com/rdaniel1105/go-passkey-auth/internal/api/middleware"
)

// Deps bundles the collaborators the API needs to satisfy its handlers.
// Adding a new endpoint that needs a new collaborator means adding a field
// here, not threading values through the call site.
type Deps struct {
	Logger   *slog.Logger
	Auth     *handler.AuthHandler
	User     *handler.UserHandler
	Sessions middleware.SessionStore
}

// New builds the chi router. All routes are prefixed with /api/v1; health
// endpoints live at the root and are added in a later task.
func New(deps Deps) http.Handler {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))

	requireSession := middleware.RequireSession(deps.Sessions, deps.Logger)

	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.Post("/register/begin", deps.Auth.BeginRegister)
			r.Post("/register/complete", deps.Auth.CompleteRegister)
			r.Post("/login/begin", deps.Auth.BeginLogin)
			r.Post("/login/complete", deps.Auth.CompleteLogin)
			r.Post("/logout", deps.Auth.Logout)
		})

		r.Route("/users/me", func(r chi.Router) {
			r.Use(requireSession)
			r.Get("/", deps.User.Me)
			r.Get("/credentials", deps.User.ListCredentials)
			r.Delete("/credentials/{id}", deps.User.DeleteCredential)
		})
	})

	return r
}
