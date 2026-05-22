package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
)

// UserStore persists users in Postgres. All methods take a context and return
// domain.User values; pgx errors are wrapped, and the unique-violation on a
// non-guest username is mapped to domain.ErrUsernameTaken.
type UserStore struct {
	pool *pgxpool.Pool
}

// NewUserStore returns a UserStore backed by the given pool.
func NewUserStore(pool *pgxpool.Pool) *UserStore {
	return &UserStore{pool: pool}
}

// CreateGuest inserts an anonymous user with is_guest = true. The username is
// a placeholder (callers typically pass something like "guest-<short-uuid>")
// because the partial unique index on username only constrains non-guest rows.
func (s *UserStore) CreateGuest(ctx context.Context, username, displayName string) (*domain.User, error) {
	const q = `
		INSERT INTO users (username, display_name, is_guest)
		VALUES ($1, $2, TRUE)
		RETURNING id, username, display_name, is_guest, created_at, promoted_at
	`

	row := s.pool.QueryRow(ctx, q, username, displayName)

	return scanUser(row)
}

// CreateRegistered inserts a non-guest user. Returns ErrUsernameTaken if the
// username already exists among registered users.
func (s *UserStore) CreateRegistered(ctx context.Context, username, displayName string) (*domain.User, error) {
	const q = `
		INSERT INTO users (username, display_name, is_guest)
		VALUES ($1, $2, FALSE)
		RETURNING id, username, display_name, is_guest, created_at, promoted_at
	`

	row := s.pool.QueryRow(ctx, q, username, displayName)

	u, err := scanUser(row)
	if err == nil {
		return u, nil
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return nil, domain.ErrUsernameTaken
	}

	return nil, err
}

// GetByID returns the user with the given id or ErrUserNotFound.
func (s *UserStore) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	const q = `
		SELECT id, username, display_name, is_guest, created_at, promoted_at
		FROM users
		WHERE id = $1
	`

	return scanUser(s.pool.QueryRow(ctx, q, id))
}

// GetByUsername returns the registered (non-guest) user with the given
// username or ErrUserNotFound. Guests are ignored on purpose — they have
// placeholder usernames that are not meant to be looked up by name.
func (s *UserStore) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	const q = `
		SELECT id, username, display_name, is_guest, created_at, promoted_at
		FROM users
		WHERE username = $1 AND is_guest = FALSE
	`

	return scanUser(s.pool.QueryRow(ctx, q, username))
}

// PromoteGuest flips a guest user to registered, assigns the chosen username,
// and stamps promoted_at. Returns ErrUsernameTaken if the username is already
// claimed by another registered user, and ErrUserNotFound if no guest row
// matches the id.
func (s *UserStore) PromoteGuest(ctx context.Context, id uuid.UUID, username, displayName string) (*domain.User, error) {
	const q = `
		UPDATE users
		SET username     = $2,
		    display_name = $3,
		    is_guest     = FALSE,
		    promoted_at  = now()
		WHERE id = $1 AND is_guest = TRUE
		RETURNING id, username, display_name, is_guest, created_at, promoted_at
	`

	row := s.pool.QueryRow(ctx, q, id, username, displayName)

	u, err := scanUser(row)
	if err == nil {
		return u, nil
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return nil, domain.ErrUsernameTaken
	}

	return nil, err
}

func scanUser(row pgx.Row) (*domain.User, error) {
	var u domain.User
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.IsGuest, &u.CreatedAt, &u.PromotedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}

	return &u, nil
}
