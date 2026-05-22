package webauthn

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsAcceptedAttestation(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"none", true},
		{"packed", true},
		{"tpm", true},
		{"android-key", true},
		{"android-safetynet", true},
		{"fido-u2f", true},
		{"apple", true},
		{"", true},          // treated as "none"
		{"unknown", false},  // policy: reject anything not in the explicit set
		{"PACKED", false},   // case-sensitive on purpose
		{"none-plus", false},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			require.New(t).Equal(tc.want, IsAcceptedAttestation(tc.in))
		})
	}
}
