package storage

import (
	"context"
	"errors"

	registrationv1 "go.zenithar.org/solid/api/gen/go/oidc/registration/v1"
)

// ErrNotFound is returned when the query return no result.
var ErrNotFound = errors.New("no result found")

//go:generate mockgen -destination mock/clientreader.gen.go -package mock go.zenithar.org/solid/pkg/storage ClientReader

// ClientReader defines client storage read-only operation contract.
type ClientReader interface {
	Get(ctx context.Context, id string) (*registrationv1.Client, error)
}

//go:generate mockgen -destination mock/client.gen.go -package mock go.zenithar.org/solid/pkg/storage Client

// Client describes complete client storage contract.
type Client interface {
	ClientReader
}
