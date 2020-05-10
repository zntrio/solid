package client

import (
	"context"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
)

// AuthenticationProcessor describes client authentication method contract.
type AuthenticationProcessor interface {
	Authenticate(ctx context.Context, req *corev1.ClientAuthenticationRequest) (*corev1.ClientAuthenticationResponse, error)
}
