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

// CredentialStore persists WebAuthn credentials in Postgres. Soft-delete is
// enforced via deleted_at; all read methods filter out deleted rows.
type CredentialStore struct {
	pool *pgxpool.Pool
}

// NewCredentialStore returns a CredentialStore backed by the given pool.
func NewCredentialStore(pool *pgxpool.Pool) *CredentialStore {
	return &CredentialStore{pool: pool}
}

// Insert persists a freshly registered credential. Returns
// ErrCredentialExists if the credential_id collides with a live row.
func (s *CredentialStore) Insert(ctx context.Context, c *domain.Credential) (*domain.Credential, error) {
	const q = `
		INSERT INTO credentials (
			user_id, credential_id, public_key, webauthn_user_handle,
			aaguid, sign_count, transports, attestation_type,
			backup_eligible, backup_state, name
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, user_id, credential_id, public_key, webauthn_user_handle,
		          aaguid, sign_count, transports, attestation_type,
		          backup_eligible, backup_state, name, created_at, last_used_at
	`

	row := s.pool.QueryRow(ctx, q,
		c.UserID, c.CredentialID, c.PublicKey, c.WebAuthnUserHandle,
		c.AAGUID, int64(c.SignCount), c.Transports, c.AttestationType,
		c.BackupEligible, c.BackupState, c.Name,
	)

	out, err := scanCredential(row)
	if err == nil {
		return out, nil
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return nil, domain.ErrCredentialExists
	}

	return nil, err
}

// GetByCredentialID returns the live credential matching the WebAuthn
// credential id, or ErrCredentialNotFound.
func (s *CredentialStore) GetByCredentialID(ctx context.Context, credentialID []byte) (*domain.Credential, error) {
	const q = `
		SELECT id, user_id, credential_id, public_key, webauthn_user_handle,
		       aaguid, sign_count, transports, attestation_type,
		       backup_eligible, backup_state, name, created_at, last_used_at
		FROM credentials
		WHERE credential_id = $1 AND deleted_at IS NULL
	`

	return scanCredential(s.pool.QueryRow(ctx, q, credentialID))
}

// ListByUserID returns all live credentials for a user, oldest first.
func (s *CredentialStore) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Credential, error) {
	const q = `
		SELECT id, user_id, credential_id, public_key, webauthn_user_handle,
		       aaguid, sign_count, transports, attestation_type,
		       backup_eligible, backup_state, name, created_at, last_used_at
		FROM credentials
		WHERE user_id = $1 AND deleted_at IS NULL
		ORDER BY created_at ASC
	`

	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.Credential, 0)

	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}

		out = append(out, c)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credentials: %w", err)
	}

	return out, nil
}

// UpdateAfterAssertion writes the post-authentication state of a credential:
// the new sign counter, the backup eligibility/state flags as observed on
// this assertion, and last_used_at = now(). Returns ErrCredentialNotFound if
// the row no longer exists (e.g. deleted between begin and complete).
func (s *CredentialStore) UpdateAfterAssertion(ctx context.Context, id uuid.UUID, signCount uint32, backupEligible, backupState bool) error {
	const q = `
		UPDATE credentials
		SET sign_count      = $2,
		    backup_eligible = $3,
		    backup_state    = $4,
		    last_used_at    = now()
		WHERE id = $1 AND deleted_at IS NULL
	`

	tag, err := s.pool.Exec(ctx, q, id, int64(signCount), backupEligible, backupState)
	if err != nil {
		return fmt.Errorf("update credential: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrCredentialNotFound
	}

	return nil
}

// SoftDelete marks a credential deleted, but only if the user has more than
// one live credential. Returns ErrLastCredential if this would leave the
// user with no way to authenticate, and ErrCredentialNotFound if the row
// does not exist or is already deleted.
//
// The check + write run in a single transaction so two concurrent deletes
// cannot both succeed.
func (s *CredentialStore) SoftDelete(ctx context.Context, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT user_id FROM credentials
		WHERE id = $1 AND deleted_at IS NULL
		FOR UPDATE
	`, id).Scan(&userID)

	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrCredentialNotFound
	}

	if err != nil {
		return fmt.Errorf("lock credential: %w", err)
	}

	var liveCount int
	err = tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM credentials
		WHERE user_id = $1 AND deleted_at IS NULL
	`, userID).Scan(&liveCount)
	if err != nil {
		return fmt.Errorf("count live credentials: %w", err)
	}

	if liveCount <= 1 {
		return domain.ErrLastCredential
	}

	_, err = tx.Exec(ctx, `
		UPDATE credentials SET deleted_at = now() WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("soft-delete credential: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

// Rename updates the user-assigned name of a credential. Returns
// ErrCredentialNotFound if no live row matches.
func (s *CredentialStore) Rename(ctx context.Context, id uuid.UUID, name string) error {
	const q = `
		UPDATE credentials SET name = $2
		WHERE id = $1 AND deleted_at IS NULL
	`

	tag, err := s.pool.Exec(ctx, q, id, name)
	if err != nil {
		return fmt.Errorf("rename credential: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrCredentialNotFound
	}

	return nil
}

func scanCredential(row pgx.Row) (*domain.Credential, error) {
	var (
		c     domain.Credential
		count int64
	)

	err := row.Scan(
		&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.WebAuthnUserHandle,
		&c.AAGUID, &count, &c.Transports, &c.AttestationType,
		&c.BackupEligible, &c.BackupState, &c.Name, &c.CreatedAt, &c.LastUsedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrCredentialNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("scan credential: %w", err)
	}

	c.SignCount = uint32(count)
	return &c, nil
}
