package authorization

import (
	"context"
	"fmt"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/internal/services"
	"go.zenithar.org/solid/pkg/authorization"
	"go.zenithar.org/solid/pkg/rfcerrors"
	"go.zenithar.org/solid/pkg/storage"
)

type service struct {
	codeGenerator authorization.CodeGenerator
	clients       storage.ClientReader
}

// New build and returns an authorization service implementation.
func New(codeGenerator authorization.CodeGenerator, clients storage.ClientReader) services.Authorization {
	return &service{
		codeGenerator: codeGenerator,
		clients:       clients,
	}
}

// -----------------------------------------------------------------------------

func (s *service) Authorize(ctx context.Context, req *corev1.AuthenticationRequest) (*corev1.AuthenticationResponse, error) {
	res := &corev1.AuthenticationResponse{}

	// Validate request
	if err := ValidateAuthorization(ctx, req); err != nil {
		res.Error = err
		return res, fmt.Errorf("unable to validate authorization request")
	}

	// Check client ID
	client, err := s.clients.Get(ctx, req.ClientId)
	if err != nil {
		res.Error = rfcerrors.InvalidRequest(req.State)
		return res, fmt.Errorf("unable to retrieve client details: %w", err)
	}

	_ = client

	// Generate authorization code
	if res.Code, err = s.codeGenerator.Generate(ctx); err != nil {
		res.Error = rfcerrors.ServerError(req.State)
		return res, fmt.Errorf("unable to generate authorization code: %w", err)
	}

	// Assign state to response
	res.State = req.State

	return res, nil
}
