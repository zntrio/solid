package jwk

import (
	"context"

	"github.com/square/go-jose/v3"
)

// KeySetProviderFunc defines key set provider contract.
type KeySetProviderFunc func(ctx context.Context) (*jose.JSONWebKeySet, error)

// KeyProviderFunc defines key provider contract.
type KeyProviderFunc func(ctx context.Context) (*jose.JSONWebKey, error)
