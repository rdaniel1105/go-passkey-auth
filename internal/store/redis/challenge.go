package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
)

const challengeKeyPrefix = "challenge:"

// ChallengeStore persists WebAuthn session data (challenge + ceremony state)
// keyed by an opaque session id. The contract is one-shot consume: Take
// returns the bytes and deletes the key in a single atomic operation, so a
// captured session id cannot be replayed even within the TTL window.
//
// The payload is opaque to this store — callers serialize whatever
// go-webauthn's SessionData looks like.
type ChallengeStore struct {
	client *redis.Client
	ttl    time.Duration
}

// NewChallengeStore returns a ChallengeStore that writes keys with the given
// TTL. The TTL should be short (5 minutes per PRD).
func NewChallengeStore(client *redis.Client, ttl time.Duration) *ChallengeStore {
	return &ChallengeStore{client: client, ttl: ttl}
}

// Save stores the ceremony payload under sessionID with the configured TTL.
// Overwrites any existing key for the same id (rare; usually only happens
// if a client retries /begin before the first attempt completed).
func (s *ChallengeStore) Save(ctx context.Context, sessionID string, payload []byte) error {
	if err := s.client.Set(ctx, challengeKeyPrefix+sessionID, payload, s.ttl).Err(); err != nil {
		return fmt.Errorf("save challenge: %w", err)
	}

	return nil
}

// Take reads the payload and atomically deletes the key using GETDEL
// (Redis ≥ 6.2). Returns ErrChallengeNotFound if the key is absent — which
// covers expiry, never-existed, and replay attempts.
func (s *ChallengeStore) Take(ctx context.Context, sessionID string) ([]byte, error) {
	raw, err := s.client.GetDel(ctx, challengeKeyPrefix+sessionID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, domain.ErrChallengeNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("take challenge: %w", err)
	}

	return raw, nil
}
