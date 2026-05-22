package redis

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
)

func TestSessionStore_CreateAndGet(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewSessionStore(testClient, time.Hour)
	ctx := context.Background()

	userID := uuid.New()
	token, err := store.Create(ctx, userID)
	c.NoError(err)
	c.NotEmpty(token)

	got, err := store.Get(ctx, token)
	c.NoError(err)
	c.Equal(userID, got)
}

func TestSessionStore_Get_NotFound(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewSessionStore(testClient, time.Hour)

	_, err := store.Get(context.Background(), "does-not-exist")
	c.ErrorIs(err, domain.ErrSessionNotFound)
}

func TestSessionStore_Delete_Idempotent(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewSessionStore(testClient, time.Hour)
	ctx := context.Background()

	token, err := store.Create(ctx, uuid.New())
	c.NoError(err)

	c.NoError(store.Delete(ctx, token))
	c.NoError(store.Delete(ctx, token)) // second delete must not error

	_, err = store.Get(ctx, token)
	c.ErrorIs(err, domain.ErrSessionNotFound)
}

func TestSessionStore_TTLExpiry(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	// 50ms TTL — short enough to expire inside the test without flaking.
	store := NewSessionStore(testClient, 50*time.Millisecond)
	ctx := context.Background()

	token, err := store.Create(ctx, uuid.New())
	c.NoError(err)

	time.Sleep(150 * time.Millisecond)

	_, err = store.Get(ctx, token)
	c.ErrorIs(err, domain.ErrSessionNotFound)
}

func TestSessionStore_TokensAreUnique(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewSessionStore(testClient, time.Hour)
	ctx := context.Background()

	seen := make(map[string]struct{}, 32)
	for range 32 {
		token, err := store.Create(ctx, uuid.New())
		c.NoError(err)
		_, dup := seen[token]
		c.False(dup, "session token collided: %s", token)
		seen[token] = struct{}{}
	}
}
