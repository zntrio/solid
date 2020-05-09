package storage

import (
	"context"
	"fmt"

	registrationv1 "go.zenithar.org/solid/api/gen/go/oidc/registration/v1"
	"go.zenithar.org/solid/pkg/storage"
)

type clientStorage struct {
}

// Clients returns a client manager.
func Clients() storage.Client {
	return &clientStorage{}
}

// -----------------------------------------------------------------------------

func (s *clientStorage) Get(ctx context.Context, id string) (*registrationv1.Client, error) {
	return nil, fmt.Errorf("not implemented")
}
