package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/rdaniel1105/go-passkey-auth/internal/api/middleware"
	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
)

// userReadStore is the slice of UserStore the user handler depends on.
type userReadStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

// credentialReadStore is the slice of CredentialStore the user handler
// depends on. SoftDelete owns the last-credential guard; the handler maps
// the sentinel to a stable response code.
type credentialReadStore interface {
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Credential, error)
	SoftDelete(ctx context.Context, id uuid.UUID) error
}

// UserDeps bundles the collaborators the UserHandler needs.
type UserDeps struct {
	Logger      *slog.Logger
	Users       userReadStore
	Credentials credentialReadStore
}

// UserHandler implements the /users/me/* endpoints.
type UserHandler struct {
	logger      *slog.Logger
	users       userReadStore
	credentials credentialReadStore
}

type meResponse struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	IsGuest     bool   `json:"is_guest"`
}

type credentialResponse struct {
	ID             string     `json:"id"`
	Name           *string    `json:"name,omitempty"`
	AAGUID         *string    `json:"aaguid,omitempty"`
	Transports     []string   `json:"transports"`
	BackupEligible bool       `json:"backup_eligible"`
	BackupState    bool       `json:"backup_state"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
}

// NewUser constructs a UserHandler from its dependencies.
func NewUser(deps UserDeps) *UserHandler {
	return &UserHandler{
		logger:      deps.Logger,
		users:       deps.Users,
		credentials: deps.Credentials,
	}
}

// Me handles GET /users/me. Returns the authenticated user's profile.
// Requires the RequireSession middleware to have run.
func (h *UserHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, h.logger, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.users.GetByID(r.Context(), userID)
	if errors.Is(err, domain.ErrUserNotFound) {
		// Session resolved to a deleted user — treat as unauthenticated.
		writeError(w, h.logger, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err != nil {
		h.logger.Error("user me: get user", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	writeJSON(w, h.logger, http.StatusOK, meResponse{
		UserID:      user.ID.String(),
		Username:    user.Username,
		DisplayName: user.DisplayName,
		IsGuest:     user.IsGuest,
	})
}

// ListCredentials handles GET /users/me/credentials.
func (h *UserHandler) ListCredentials(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, h.logger, http.StatusUnauthorized, "unauthorized")
		return
	}

	creds, err := h.credentials.ListByUserID(r.Context(), userID)
	if err != nil {
		h.logger.Error("list credentials", "err", err, "user_id", userID)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	out := make([]credentialResponse, 0, len(creds))
	for _, c := range creds {
		item := credentialResponse{
			ID:             c.ID.String(),
			Name:           c.Name,
			Transports:     c.Transports,
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
			CreatedAt:      c.CreatedAt,
			LastUsedAt:     c.LastUsedAt,
		}

		if c.AAGUID != nil {
			id := c.AAGUID.String()
			item.AAGUID = &id
		}

		out = append(out, item)
	}

	writeJSON(w, h.logger, http.StatusOK, out)
}

// DeleteCredential handles DELETE /users/me/credentials/{id}.
//
// The last-credential guard lives in the credential store's SoftDelete:
// the check + write run in a transaction so concurrent deletes cannot
// both succeed past the guard. We just translate the sentinel here.
//
// We do NOT verify that the credential belongs to the authenticated user
// at the handler level — the store doesn't expose a (user, credential)
// lookup. Instead we check ownership before calling SoftDelete: list the
// user's credentials and require id to be among them. This costs one
// extra query per delete; it's the right boundary check.
func (h *UserHandler) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, h.logger, http.StatusUnauthorized, "unauthorized")
		return
	}

	idParam := chi.URLParam(r, "id")
	credID, err := uuid.Parse(idParam)
	if err != nil {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request")
		return
	}

	owned, err := h.credentials.ListByUserID(r.Context(), userID)
	if err != nil {
		h.logger.Error("delete credential: list", "err", err, "user_id", userID)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	var found bool
	for _, c := range owned {
		if c.ID == credID {
			found = true
			break
		}
	}

	if !found {
		// Don't disclose whether the credential exists for another user —
		// always 404 from this user's perspective.
		writeError(w, h.logger, http.StatusNotFound, "not_found")
		return
	}

	err = h.credentials.SoftDelete(r.Context(), credID)
	if errors.Is(err, domain.ErrLastCredential) {
		writeError(w, h.logger, http.StatusConflict, "last_credential")
		return
	}

	if errors.Is(err, domain.ErrCredentialNotFound) {
		writeError(w, h.logger, http.StatusNotFound, "not_found")
		return
	}

	if err != nil {
		h.logger.Error("delete credential: soft delete", "err", err, "credential_id", credID)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
