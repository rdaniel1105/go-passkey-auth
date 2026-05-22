package middleware

import (
	"context"

	"github.com/google/uuid"
)

// contextWithUserIDForTest is the test-only inverse of UserIDFromContext.
// Production code reaches the context via RequireSession; tests for code
// that *reads* the user id (e.g. RequestLogger) need to plant one without
// running the whole session-store path.
func contextWithUserIDForTest(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDContextKey, id)
}
