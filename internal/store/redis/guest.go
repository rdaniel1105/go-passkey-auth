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

const guestKeyPrefix = "guest:"

// GuestStore maps anonymous guest tokens to their (guest) user ID. Used to
// give an unregistered visitor a place to anchor state (e.g. a wishlist)
// until they complete passkey registration and get promoted.
type GuestStore struct {
	client *redis.Client
	ttl    time.Duration
}

// NewGuestStore returns a GuestStore that writes keys with the given TTL.
func NewGuestStore(client *redis.Client, ttl time.Duration) *GuestStore {
	return &GuestStore{client: client, ttl: ttl}
}

// Create issues a fresh guest token bound to userID and stores it with the
// configured TTL.
func (s *GuestStore) Create(ctx context.Context, userID uuid.UUID) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}

	if err := s.client.Set(ctx, guestKeyPrefix+token, userID.String(), s.ttl).Err(); err != nil {
		return "", fmt.Errorf("set guest: %w", err)
	}

	return token, nil
}

// Get resolves a guest token to its user ID. Returns ErrGuestNotFound if the
// token has expired or was never issued.
func (s *GuestStore) Get(ctx context.Context, token string) (uuid.UUID, error) {
	raw, err := s.client.Get(ctx, guestKeyPrefix+token).Result()
	if errors.Is(err, redis.Nil) {
		return uuid.Nil, domain.ErrGuestNotFound
	}

	if err != nil {
		return uuid.Nil, fmt.Errorf("get guest: %w", err)
	}

	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, fmt.Errorf("parse guest user id: %w", err)
	}

	return id, nil
}

// Delete clears a guest token, used after a successful promotion or login
// with the registered account. Idempotent.
func (s *GuestStore) Delete(ctx context.Context, token string) error {
	if err := s.client.Del(ctx, guestKeyPrefix+token).Err(); err != nil {
		return fmt.Errorf("delete guest: %w", err)
	}

	return nil
}
