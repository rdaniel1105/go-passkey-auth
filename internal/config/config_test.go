package config

import (
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoad_AllValid(t *testing.T) {
	c := require.New(t)

	withEnv(t, map[string]string{
		"HTTP_ADDR":       ":8080",
		"DATABASE_URL":    "postgres://u:p@h/d",
		"REDIS_URL":       "redis://r:6379/0",
		"RP_ID":           "localhost",
		"RP_DISPLAY_NAME": "test",
		"RP_ORIGINS":      "http://localhost:8080, http://localhost:3000",
		"SESSION_TTL":     "24h",
		"CHALLENGE_TTL":   "5m",
		"GUEST_TTL":       "1h",
	})

	cfg, err := Load()
	c.NoError(err)
	c.Equal(24*time.Hour, cfg.SessionTTL)
	c.Equal(5*time.Minute, cfg.ChallengeTTL)
	c.Equal(time.Hour, cfg.GuestTTL)
	c.Len(cfg.RPOrigins, 2)
	c.Equal("http://localhost:8080", cfg.RPOrigins[0])
	c.Equal("http://localhost:3000", cfg.RPOrigins[1])
}

func TestLoad_MissingRequired(t *testing.T) {
	base := map[string]string{
		"HTTP_ADDR":       ":8080",
		"DATABASE_URL":    "postgres://u:p@h/d",
		"REDIS_URL":       "redis://r:6379/0",
		"RP_ID":           "localhost",
		"RP_DISPLAY_NAME": "test",
		"RP_ORIGINS":      "http://localhost:8080",
		"SESSION_TTL":     "24h",
		"CHALLENGE_TTL":   "5m",
		"GUEST_TTL":       "1h",
	}

	cases := []struct {
		drop string
		want error
	}{
		{"HTTP_ADDR", ErrMissingHTTPAddr},
		{"DATABASE_URL", ErrMissingDatabaseURL},
		{"REDIS_URL", ErrMissingRedisURL},
		{"RP_ID", ErrMissingRPID},
		{"RP_DISPLAY_NAME", ErrMissingRPDisplayName},
		{"RP_ORIGINS", ErrMissingRPOrigins},
	}

	for _, tc := range cases {
		t.Run(tc.drop, func(t *testing.T) {
			c := require.New(t)

			env := copyMap(base)
			env[tc.drop] = ""
			withEnv(t, env)

			_, err := Load()
			c.ErrorIs(err, tc.want)
		})
	}
}

func TestLoad_InvalidDuration(t *testing.T) {
	c := require.New(t)

	withEnv(t, map[string]string{
		"HTTP_ADDR":       ":8080",
		"DATABASE_URL":    "postgres://u:p@h/d",
		"REDIS_URL":       "redis://r:6379/0",
		"RP_ID":           "localhost",
		"RP_DISPLAY_NAME": "test",
		"RP_ORIGINS":      "http://localhost:8080",
		"SESSION_TTL":     "nope",
		"CHALLENGE_TTL":   "5m",
		"GUEST_TTL":       "1h",
	})

	_, err := Load()
	c.ErrorIs(err, ErrInvalidSessionTTL)
}

func TestLoad_NegativeDuration(t *testing.T) {
	c := require.New(t)

	withEnv(t, map[string]string{
		"HTTP_ADDR":       ":8080",
		"DATABASE_URL":    "postgres://u:p@h/d",
		"REDIS_URL":       "redis://r:6379/0",
		"RP_ID":           "localhost",
		"RP_DISPLAY_NAME": "test",
		"RP_ORIGINS":      "http://localhost:8080",
		"SESSION_TTL":     "24h",
		"CHALLENGE_TTL":   "-5m",
		"GUEST_TTL":       "1h",
	})

	_, err := Load()
	c.ErrorIs(err, ErrInvalidChallengeTTL)
}

func withEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	maps.Copy(out, m)
	return out
}
