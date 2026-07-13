package knownhosts

import "testing"

func TestIsAuthenticationError(t *testing.T) {
	cases := []struct {
		message string
		want    bool
	}{
		{"ssh: handshake failed: ssh: unable to authenticate", true},
		{"permission denied (publickey)", true},
		{"dial tcp: connection refused", false},
		{"HOST_KEY_MISMATCH", false},
	}
	for _, testCase := range cases {
		if got := IsAuthenticationError(testCase.message); got != testCase.want {
			t.Errorf("IsAuthenticationError(%q) = %v, want %v", testCase.message, got, testCase.want)
		}
	}
}
