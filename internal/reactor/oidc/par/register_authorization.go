package par

import (
	"context"
	"fmt"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/internal/services"
	"go.zenithar.org/solid/pkg/reactor"
	"go.zenithar.org/solid/pkg/types"
)

// RegisterAuthorizationHandler handles authorization registration requests.
var RegisterAuthorizationHandler = func(authorization services.Authorization) reactor.HandlerFunc {
	return func(ctx context.Context, r interface{}) (interface{}, error) {
		// Check nil request
		if types.IsNil(r) {
			return nil, fmt.Errorf("unable to process nil request")
		}

		// Check request type
		req, ok := r.(*corev1.RegistrationRequest)
		if !ok {
			return nil, fmt.Errorf("invalid request type %T", req)
		}

		// Delegate to service
		return authorization.Register(ctx, req)
	}
}
