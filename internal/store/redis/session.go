package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
)

const sessionKeyPrefix = "session:"

// SessionStore maps opaque session tokens to user IDs in Redis with a fixed
// TTL. Tokens are issued via Create and resolved via Get; logout is Delete.
type SessionStore struct {
	client *redis.Client
	ttl    time.Duration
}

// NewSessionStore returns a SessionStore that writes keys with the given TTL.
func NewSessionStore(client *redis.Client, ttl time.Duration) *SessionStore {
	return &SessionStore{client: client, ttl: ttl}
}

// Create issues a fresh session token bound to userID and stores it with the
// configured TTL. The returned token is what the caller sets in the
// HttpOnly cookie.
func (s *SessionStore) Create(ctx context.Context, userID uuid.UUID) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}

	if err := s.client.Set(ctx, sessionKeyPrefix+token, userID.String(), s.ttl).Err(); err != nil {
		return "", fmt.Errorf("set session: %w", err)
	}

	return token, nil
}

// Get resolves a session token to its user ID. Returns ErrSessionNotFound if
// the token has expired, was never issued, or was already deleted.
func (s *SessionStore) Get(ctx context.Context, token string) (uuid.UUID, error) {
	raw, err := s.client.Get(ctx, sessionKeyPrefix+token).Result()
	if errors.Is(err, redis.Nil) {
		return uuid.Nil, domain.ErrSessionNotFound
	}

	if err != nil {
		return uuid.Nil, fmt.Errorf("get session: %w", err)
	}

	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, fmt.Errorf("parse session user id: %w", err)
	}

	return id, nil
}

// Delete invalidates a session. Idempotent: deleting a missing token is not
// an error (a double-logout should not surface as a failure).
func (s *SessionStore) Delete(ctx context.Context, token string) error {
	if err := s.client.Del(ctx, sessionKeyPrefix+token).Err(); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}
