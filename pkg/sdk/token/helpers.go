package token

import (
	"time"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
)

// IsUsable check token usability constraint.
func IsUsable(t *corev1.Token) bool {
	// Check arguments
	if t == nil {
		return false
	}
	if t.Metadata == nil {
		return false
	}

	// Check expiration
	now := uint64(time.Now().Unix())
	if t.Metadata.ExpiresAt < now {
		return false
	}
	if t.Metadata.NotBefore > now {
		return false
	}

	// No error
	return true
}
