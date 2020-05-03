package authorization

import (
	"context"

	"go.zenithar.org/solid/pkg/rfcerrors"

	"github.com/golang/protobuf/ptypes/wrappers"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
)

// ValidateAuthorization validates authorization request.
func ValidateAuthorization(ctx context.Context, req *corev1.AuthenticationRequest) *corev1.Error {
	// Check req nullity
	if req == nil {
		return &corev1.Error{
			Err: "invalid_request",
			ErrorDescription: &wrappers.StringValue{
				Value: "request is nil",
			},
		}
	}

	// Validate request attributes
	if req.State == "" {
		return rfcerrors.InvalidRequest("<missing>")
	}

	if req.Scope == "" || req.ResponseType == "" || req.ClientId == "" || req.RedirectUri == "" {
		return rfcerrors.InvalidRequest(req.State)
	}

	// Return result
	return nil
}
