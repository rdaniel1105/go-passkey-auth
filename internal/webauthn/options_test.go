package webauthn

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func validCfg() Config {
	return Config{
		RPID:            "localhost",
		RPDisplayName:   "go-passkey-auth",
		RPOrigins:       []string{"http://localhost:8080"},
		CeremonyTimeout: 5 * time.Minute,
	}
}

func TestNewService_Valid(t *testing.T) {
	c := require.New(t)

	svc, err := NewService(validCfg())
	c.NoError(err)
	c.NotNil(svc)
}

func TestNewService_MissingFields(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want error
	}{
		{"no RPID", func(c *Config) { c.RPID = "" }, ErrConfigMissingRPID},
		{"no display name", func(c *Config) { c.RPDisplayName = "" }, ErrConfigMissingRPDisplayName},
		{"no origins", func(c *Config) { c.RPOrigins = nil }, ErrConfigMissingRPOrigins},
		{"zero timeout", func(c *Config) { c.CeremonyTimeout = 0 }, ErrConfigInvalidTimeout},
		{"negative timeout", func(c *Config) { c.CeremonyTimeout = -time.Second }, ErrConfigInvalidTimeout},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := require.New(t)

			cfg := validCfg()
			tc.mut(&cfg)

			_, err := NewService(cfg)
			c.ErrorIs(err, tc.want)
		})
	}
}
