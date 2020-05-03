package services

import (
	"context"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
)

// CodeGenerator is the function contract used by authorization_code generator.
type CodeGenerator func(context.Context) (string, error)

// Authorization describes authorization request processor.
type Authorization interface {
	// Authorize a request.
	Authorize(ctx context.Context, req *corev1.AuthenticationRequest) (*corev1.AuthenticationResponse, error)
}
