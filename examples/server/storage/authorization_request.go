package storage

import (
	"context"
	"fmt"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/pkg/storage"
)

type authorizationRequestStorage struct {
}

// AuthorizationRequests returns an authorization request manager.
func AuthorizationRequests() storage.AuthorizationRequest {
	return &authorizationRequestStorage{}
}

// -----------------------------------------------------------------------------

func (s *authorizationRequestStorage) Register(ctx context.Context, req *corev1.AuthorizationRequest) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (s *authorizationRequestStorage) Delete(ctx context.Context, requestURI string) error {
	return fmt.Errorf("not implemented")
}

func (s *authorizationRequestStorage) GetByRequestURI(ctx context.Context, requestURI string) (*corev1.AuthorizationRequest, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *authorizationRequestStorage) GetByCode(ctx context.Context, code string) (*corev1.AuthorizationRequest, error) {
	return nil, fmt.Errorf("not implemented")
}
