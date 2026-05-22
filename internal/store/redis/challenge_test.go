package redis

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
)

func TestChallengeStore_SaveAndTake(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewChallengeStore(testClient, time.Minute)
	ctx := context.Background()

	payload := []byte(`{"challenge":"abc","user_id":"u"}`)
	c.NoError(store.Save(ctx, "sess-1", payload))

	got, err := store.Take(ctx, "sess-1")
	c.NoError(err)
	c.Equal(payload, got)
}

func TestChallengeStore_Take_IsOneShot(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewChallengeStore(testClient, time.Minute)
	ctx := context.Background()

	c.NoError(store.Save(ctx, "sess-2", []byte("payload")))

	_, err := store.Take(ctx, "sess-2")
	c.NoError(err)

	// Second take is the replay attempt — must fail.
	_, err = store.Take(ctx, "sess-2")
	c.ErrorIs(err, domain.ErrChallengeNotFound)
}

func TestChallengeStore_Take_NotFound(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewChallengeStore(testClient, time.Minute)

	_, err := store.Take(context.Background(), "never-existed")
	c.ErrorIs(err, domain.ErrChallengeNotFound)
}

func TestChallengeStore_TTLExpiry(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewChallengeStore(testClient, 50*time.Millisecond)
	ctx := context.Background()

	c.NoError(store.Save(ctx, "sess-3", []byte("payload")))

	time.Sleep(150 * time.Millisecond)

	_, err := store.Take(ctx, "sess-3")
	c.ErrorIs(err, domain.ErrChallengeNotFound)
}

func TestChallengeStore_Save_Overwrite(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewChallengeStore(testClient, time.Minute)
	ctx := context.Background()

	c.NoError(store.Save(ctx, "sess-4", []byte("first")))
	c.NoError(store.Save(ctx, "sess-4", []byte("second")))

	got, err := store.Take(ctx, "sess-4")
	c.NoError(err)
	c.Equal([]byte("second"), got)
}
