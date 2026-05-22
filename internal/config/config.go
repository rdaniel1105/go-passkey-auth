// Package config loads service configuration from environment variables.
//
// Local development reads a `.env` file via godotenv when present. In Docker
// and production the variables come from the real environment; the .env load
// silently no-ops if the file is absent.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Sentinel errors returned by Load when a required variable is missing or invalid.
// Callers can match with errors.Is to react to specific misconfigurations.
var (
	// ErrMissingHTTPAddr is returned when HTTP_ADDR is empty.
	ErrMissingHTTPAddr = errors.New("HTTP_ADDR is required")
	// ErrMissingDatabaseURL is returned when DATABASE_URL is empty.
	ErrMissingDatabaseURL = errors.New("DATABASE_URL is required")
	// ErrMissingRedisURL is returned when REDIS_URL is empty.
	ErrMissingRedisURL = errors.New("REDIS_URL is required")
	// ErrMissingRPID is returned when RP_ID is empty.
	ErrMissingRPID = errors.New("RP_ID is required")
	// ErrMissingRPDisplayName is returned when RP_DISPLAY_NAME is empty.
	ErrMissingRPDisplayName = errors.New("RP_DISPLAY_NAME is required")
	// ErrMissingRPOrigins is returned when RP_ORIGINS does not contain at least
	// one non-empty origin. The list backs the WebAuthn origin allowlist.
	ErrMissingRPOrigins = errors.New("RP_ORIGINS must list at least one origin")
	// ErrInvalidSessionTTL is returned when SESSION_TTL is missing or not a
	// positive Go duration (e.g. "24h").
	ErrInvalidSessionTTL = errors.New("SESSION_TTL must be a positive Go duration")
	// ErrInvalidChallengeTTL is returned when CHALLENGE_TTL is missing or not a
	// positive Go duration (e.g. "5m").
	ErrInvalidChallengeTTL = errors.New("CHALLENGE_TTL must be a positive Go duration")
	// ErrInvalidGuestTTL is returned when GUEST_TTL is missing or not a
	// positive Go duration (e.g. "1h").
	ErrInvalidGuestTTL = errors.New("GUEST_TTL must be a positive Go duration")
)

// Config holds the runtime configuration for the passkey service. Values are
// populated by Load from environment variables and validated before use.
type Config struct {
	// HTTPAddr is the address the HTTP server binds to (e.g. ":8080").
	HTTPAddr string
	// DatabaseURL is the Postgres connection string used by the user and
	// credential stores.
	DatabaseURL string
	// RedisURL is the Redis connection string used for sessions, challenges,
	// and guest tokens.
	RedisURL string
	// RPID is the WebAuthn Relying Party identifier (typically the registrable
	// domain, e.g. "example.com" or "localhost" in development).
	RPID string
	// RPDisplayName is the human-readable name shown in browser passkey UI.
	RPDisplayName string
	// RPOrigins is the allowlist of origins accepted during attestation and
	// assertion verification (e.g. "https://app.example.com").
	RPOrigins []string
	// SessionTTL is how long an authenticated session lives in Redis.
	SessionTTL time.Duration
	// ChallengeTTL is how long a registration or authentication challenge
	// remains valid in Redis. The challenge is also deleted on first use.
	ChallengeTTL time.Duration
	// GuestTTL is how long an anonymous guest session lives in Redis before
	// the user must register or restart the flow.
	GuestTTL time.Duration
}

// Load reads configuration from the environment. A `.env` file at the working
// directory is loaded first if present; existing env vars are not overridden.
func Load() (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{
		HTTPAddr:      os.Getenv("HTTP_ADDR"),
		DatabaseURL:   os.Getenv("DATABASE_URL"),
		RedisURL:      os.Getenv("REDIS_URL"),
		RPID:          os.Getenv("RP_ID"),
		RPDisplayName: os.Getenv("RP_DISPLAY_NAME"),
		RPOrigins:     splitAndTrim(os.Getenv("RP_ORIGINS"), ","),
	}

	sessionTTL, err := parseDuration(os.Getenv("SESSION_TTL"), ErrInvalidSessionTTL)
	if err != nil {
		return nil, err
	}
	cfg.SessionTTL = sessionTTL

	challengeTTL, err := parseDuration(os.Getenv("CHALLENGE_TTL"), ErrInvalidChallengeTTL)
	if err != nil {
		return nil, err
	}
	cfg.ChallengeTTL = challengeTTL

	guestTTL, err := parseDuration(os.Getenv("GUEST_TTL"), ErrInvalidGuestTTL)
	if err != nil {
		return nil, err
	}
	cfg.GuestTTL = guestTTL

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	switch {
	case c.HTTPAddr == "":
		return ErrMissingHTTPAddr
	case c.DatabaseURL == "":
		return ErrMissingDatabaseURL
	case c.RedisURL == "":
		return ErrMissingRedisURL
	case c.RPID == "":
		return ErrMissingRPID
	case c.RPDisplayName == "":
		return ErrMissingRPDisplayName
	case len(c.RPOrigins) == 0:
		return ErrMissingRPOrigins
	}

	return nil
}

func parseDuration(raw string, sentinel error) (time.Duration, error) {
	if raw == "" {
		return 0, sentinel
	}

	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%w: %q", sentinel, raw)
	}

	return d, nil
}

func splitAndTrim(s, sep string) []string {
	if s == "" {
		return nil
	}

	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))

	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}

	return out
}
