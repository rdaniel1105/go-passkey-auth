package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-passkey-auth/internal/domain"
)

// newTestCredential builds a credential row attached to userID with unique
// credential_id and public_key bytes derived from suffix. WebAuthnUserHandle
// is fixed-length per spec recommendations.
func newTestCredential(userID uuid.UUID, suffix byte) *domain.Credential {
	handle := make([]byte, 64)
	for i := range handle {
		handle[i] = suffix
	}

	aaguid := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	name := "test-key"

	return &domain.Credential{
		UserID:             userID,
		CredentialID:       []byte{0xCA, 0xFE, suffix},
		PublicKey:          []byte{0xBE, 0xEF, suffix},
		WebAuthnUserHandle: handle,
		AAGUID:             &aaguid,
		SignCount:          0,
		Transports:         []string{"internal", "hybrid"},
		AttestationFormat:    "none",
		AttestationType:      "none",
		BackupEligible:     true,
		BackupState:        true,
		Name:               &name,
	}
}

func seedUser(t *testing.T) uuid.UUID {
	t.Helper()

	users := NewUserStore(testPool)
	u, err := users.CreateRegistered(context.Background(), uuid.NewString(), "test")
	require.NoError(t, err)

	return u.ID
}

func TestCredentialStore_Insert(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCredentialStore(testPool)
	ctx := context.Background()
	userID := seedUser(t)

	in := newTestCredential(userID, 0x01)
	out, err := store.Insert(ctx, in)
	c.NoError(err)
	c.NotEqual(uuid.Nil, out.ID)
	c.Equal(in.CredentialID, out.CredentialID)
	c.Equal(in.WebAuthnUserHandle, out.WebAuthnUserHandle)
	c.Equal([]string{"internal", "hybrid"}, out.Transports)
	c.True(out.BackupEligible)
	c.True(out.BackupState)
	c.Equal("none", out.AttestationFormat)
	c.False(out.CreatedAt.IsZero())
	c.Nil(out.LastUsedAt)
}

func TestCredentialStore_Insert_DuplicateCredentialID(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCredentialStore(testPool)
	ctx := context.Background()
	userID := seedUser(t)

	_, err := store.Insert(ctx, newTestCredential(userID, 0x02))
	c.NoError(err)

	_, err = store.Insert(ctx, newTestCredential(userID, 0x02))
	c.ErrorIs(err, domain.ErrCredentialExists)
}

func TestCredentialStore_GetByCredentialID_NotFound(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCredentialStore(testPool)

	_, err := store.GetByCredentialID(context.Background(), []byte{0xDE, 0xAD})
	c.ErrorIs(err, domain.ErrCredentialNotFound)
}

func TestCredentialStore_ListByUserID(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCredentialStore(testPool)
	ctx := context.Background()
	userID := seedUser(t)

	for _, suffix := range []byte{0x10, 0x11, 0x12} {
		_, err := store.Insert(ctx, newTestCredential(userID, suffix))
		c.NoError(err)
	}

	list, err := store.ListByUserID(ctx, userID)
	c.NoError(err)
	c.Len(list, 3)
}

func TestCredentialStore_UpdateAfterAssertion(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCredentialStore(testPool)
	ctx := context.Background()
	userID := seedUser(t)

	cred, err := store.Insert(ctx, newTestCredential(userID, 0x20))
	c.NoError(err)
	c.Nil(cred.LastUsedAt)

	err = store.UpdateAfterAssertion(ctx, cred.ID, 42, false, false)
	c.NoError(err)

	got, err := store.GetByCredentialID(ctx, cred.CredentialID)
	c.NoError(err)
	c.Equal(uint32(42), got.SignCount)
	c.False(got.BackupEligible)
	c.False(got.BackupState)
	c.NotNil(got.LastUsedAt)
}

func TestCredentialStore_UpdateAfterAssertion_NotFound(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCredentialStore(testPool)

	err := store.UpdateAfterAssertion(context.Background(), uuid.New(), 1, false, false)
	c.ErrorIs(err, domain.ErrCredentialNotFound)
}

func TestCredentialStore_SoftDelete_LastCredentialBlocked(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCredentialStore(testPool)
	ctx := context.Background()
	userID := seedUser(t)

	cred, err := store.Insert(ctx, newTestCredential(userID, 0x30))
	c.NoError(err)

	err = store.SoftDelete(ctx, cred.ID)
	c.ErrorIs(err, domain.ErrLastCredential)

	// The credential must remain readable.
	_, err = store.GetByCredentialID(ctx, cred.CredentialID)
	c.NoError(err)
}

func TestCredentialStore_SoftDelete_Succeeds(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCredentialStore(testPool)
	ctx := context.Background()
	userID := seedUser(t)

	cred1, err := store.Insert(ctx, newTestCredential(userID, 0x40))
	c.NoError(err)

	_, err = store.Insert(ctx, newTestCredential(userID, 0x41))
	c.NoError(err)

	err = store.SoftDelete(ctx, cred1.ID)
	c.NoError(err)

	// Soft-deleted row is gone from the live view.
	_, err = store.GetByCredentialID(ctx, cred1.CredentialID)
	c.ErrorIs(err, domain.ErrCredentialNotFound)

	live, err := store.ListByUserID(ctx, userID)
	c.NoError(err)
	c.Len(live, 1)
}

func TestCredentialStore_SoftDelete_ReleasesCredentialIDForReuse(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCredentialStore(testPool)
	ctx := context.Background()
	userID := seedUser(t)

	cred1, err := store.Insert(ctx, newTestCredential(userID, 0x50))
	c.NoError(err)

	_, err = store.Insert(ctx, newTestCredential(userID, 0x51))
	c.NoError(err)

	err = store.SoftDelete(ctx, cred1.ID)
	c.NoError(err)

	// The partial unique index allows the same credential_id to be re-inserted
	// once the original is soft-deleted (e.g. re-registering the same key).
	_, err = store.Insert(ctx, newTestCredential(userID, 0x50))
	c.NoError(err)
}

func TestCredentialStore_SoftDelete_NotFound(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCredentialStore(testPool)

	err := store.SoftDelete(context.Background(), uuid.New())
	c.ErrorIs(err, domain.ErrCredentialNotFound)
}

func TestCredentialStore_Rename(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCredentialStore(testPool)
	ctx := context.Background()
	userID := seedUser(t)

	cred, err := store.Insert(ctx, newTestCredential(userID, 0x60))
	c.NoError(err)

	err = store.Rename(ctx, cred.ID, "iPhone 15")
	c.NoError(err)

	got, err := store.GetByCredentialID(ctx, cred.CredentialID)
	c.NoError(err)
	c.NotNil(got.Name)
	c.Equal("iPhone 15", *got.Name)
}

func TestCredentialStore_Rename_NotFound(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCredentialStore(testPool)

	err := store.Rename(context.Background(), uuid.New(), "nope")
	c.ErrorIs(err, domain.ErrCredentialNotFound)
}
