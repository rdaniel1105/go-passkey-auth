package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
)

func TestUserStore_CreateGuest(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewUserStore(testPool)
	ctx := context.Background()

	u, err := store.CreateGuest(ctx, "guest-1", "Guest 1")
	c.NoError(err)
	c.True(u.IsGuest)
	c.Equal("guest-1", u.Username)
	c.Equal("Guest 1", u.DisplayName)
	c.Nil(u.PromotedAt)
	c.NotEqual(uuid.Nil, u.ID)
}

func TestUserStore_CreateGuest_DuplicateUsername_Allowed(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewUserStore(testPool)
	ctx := context.Background()

	_, err := store.CreateGuest(ctx, "shared", "G1")
	c.NoError(err)

	// Partial unique index only constrains is_guest = FALSE, so duplicate
	// guest usernames must be allowed.
	_, err = store.CreateGuest(ctx, "shared", "G2")
	c.NoError(err)
}

func TestUserStore_CreateRegistered_UsernameTaken(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewUserStore(testPool)
	ctx := context.Background()

	_, err := store.CreateRegistered(ctx, "alice", "Alice")
	c.NoError(err)

	_, err = store.CreateRegistered(ctx, "alice", "Alice Two")
	c.ErrorIs(err, domain.ErrUsernameTaken)
}

func TestUserStore_GetByID_NotFound(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewUserStore(testPool)
	ctx := context.Background()

	_, err := store.GetByID(ctx, uuid.New())
	c.ErrorIs(err, domain.ErrUserNotFound)
}

func TestUserStore_GetByUsername_IgnoresGuests(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewUserStore(testPool)
	ctx := context.Background()

	_, err := store.CreateGuest(ctx, "bob", "Bob Guest")
	c.NoError(err)

	_, err = store.GetByUsername(ctx, "bob")
	c.ErrorIs(err, domain.ErrUserNotFound)

	registered, err := store.CreateRegistered(ctx, "bob-real", "Bob")
	c.NoError(err)

	got, err := store.GetByUsername(ctx, "bob-real")
	c.NoError(err)
	c.Equal(registered.ID, got.ID)
}

func TestUserStore_PromoteGuest(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewUserStore(testPool)
	ctx := context.Background()

	guest, err := store.CreateGuest(ctx, "guest-x", "X")
	c.NoError(err)

	promoted, err := store.PromoteGuest(ctx, guest.ID, "carol", "Carol")
	c.NoError(err)
	c.Equal(guest.ID, promoted.ID)
	c.False(promoted.IsGuest)
	c.Equal("carol", promoted.Username)
	c.NotNil(promoted.PromotedAt)
}

func TestUserStore_PromoteGuest_UsernameTaken(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewUserStore(testPool)
	ctx := context.Background()

	_, err := store.CreateRegistered(ctx, "dave", "Dave")
	c.NoError(err)

	guest, err := store.CreateGuest(ctx, "guest-y", "Y")
	c.NoError(err)

	_, err = store.PromoteGuest(ctx, guest.ID, "dave", "Dave Two")
	c.ErrorIs(err, domain.ErrUsernameTaken)
}

func TestUserStore_PromoteGuest_NotAGuest(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewUserStore(testPool)
	ctx := context.Background()

	registered, err := store.CreateRegistered(ctx, "eve", "Eve")
	c.NoError(err)

	_, err = store.PromoteGuest(ctx, registered.ID, "eve2", "Eve Two")
	c.ErrorIs(err, domain.ErrUserNotFound)
}
