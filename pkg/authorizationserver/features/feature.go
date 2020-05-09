package features

import (
	"go.zenithar.org/solid/internal/services"
	"go.zenithar.org/solid/pkg/reactor"
)

// Feature represents authorization server feature enabler.
type Feature func(r reactor.Reactor, authorizations services.Authorization, tokens services.Token)
