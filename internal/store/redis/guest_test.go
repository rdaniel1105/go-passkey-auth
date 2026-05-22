package redis

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
)

func TestGuestStore_CreateAndGet(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewGuestStore(testClient, time.Hour)
	ctx := context.Background()

	userID := uuid.New()
	token, err := store.Create(ctx, userID)
	c.NoError(err)
	c.NotEmpty(token)

	got, err := store.Get(ctx, token)
	c.NoError(err)
	c.Equal(userID, got)
}

func TestGuestStore_Get_NotFound(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewGuestStore(testClient, time.Hour)

	_, err := store.Get(context.Background(), "missing")
	c.ErrorIs(err, domain.ErrGuestNotFound)
}

func TestGuestStore_Delete(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewGuestStore(testClient, time.Hour)
	ctx := context.Background()

	token, err := store.Create(ctx, uuid.New())
	c.NoError(err)

	c.NoError(store.Delete(ctx, token))

	_, err = store.Get(ctx, token)
	c.ErrorIs(err, domain.ErrGuestNotFound)
}

func TestGuestStore_TokensAndSessionsUseDistinctNamespaces(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	sessions := NewSessionStore(testClient, time.Hour)
	guests := NewGuestStore(testClient, time.Hour)
	ctx := context.Background()

	// Same token value, different prefixes -> must not collide. We can't
	// force them to be equal (tokens are random) but we can prove a guest
	// token does not resolve as a session and vice versa.
	guestToken, err := guests.Create(ctx, uuid.New())
	c.NoError(err)

	_, err = sessions.Get(ctx, guestToken)
	c.ErrorIs(err, domain.ErrSessionNotFound)

	sessionToken, err := sessions.Create(ctx, uuid.New())
	c.NoError(err)

	_, err = guests.Get(ctx, sessionToken)
	c.ErrorIs(err, domain.ErrGuestNotFound)
}
