package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/davecgh/go-spew/spew"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/client"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/token/jwt"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage/inmemory"
)

// -----------------------------------------------------------------------------
type identity struct {
	Subject  string
	ClientID string
}

var (
	permissions = map[string]map[string]types.StringArray{
		"timestamp:read": {
			"t8p9duw4n2klximkv3kagaud796ul67g": {
				"", // Allow client itself
			},
			"attestation-client": {
				"", 
			},
		},
	}
)

func can(id *identity, intent string) bool {
	// Check permission request
	clients, ok := permissions[intent]
	if !ok {
		return false
	}

	// Check subject permission
	subjects, ok := clients[id.ClientID]
	if !ok {
		return false
	}

	return subjects.Contains(id.Subject)
}

// -----------------------------------------------------------------------------

func authenticateWithBearer(w http.ResponseWriter, req *http.Request, cli client.Client) (*identity, error) {
	ctx := req.Context()

	// Get token from request
	parts := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	if !strings.EqualFold(parts[0], "bearer") {
		return nil, errors.New("Authorization header must be a 'Bearer' token.")
	}

	// Prepare assertion
	assertion, err := cli.Assertion()
	if err != nil {
		return nil, fmt.Errorf("unable to prepare client authentication assertion: %w", err)
	}

	// Send introspection request to the issuer.
	t, err := cli.Introspect(ctx, assertion, parts[1])
	if err != nil {
		return nil, errors.New("Unable to get a successful token introspection response.")
	}
	spew.Dump(t)
	switch {
	case t.Status != tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE:
		return nil, errors.New("Token is inactive.")
	case t.Confirmation != nil:
		return nil, errors.New("Token requires a PoP proof to be used.")
	}

	return &identity{
		Subject:  t.Metadata.Subject,
		ClientID: t.Metadata.ClientId,
	}, nil
}

func authenticateWithDPoP(w http.ResponseWriter, req *http.Request, cli client.Client, dpopVerifier dpop.Verifier) (*identity, error) {
	ctx := req.Context()

	// Get token from request
	parts := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	if !strings.EqualFold(parts[0], "dpop") {
		return nil, errors.New("Authorization header must be a 'DPoP' token.")
	}

	// Check DPoP proof
	dpopProof := req.Header.Get("DPoP")

	// Validate dpop
	expectedJkt, err := dpopVerifier.Verify(ctx, req.Method, dpop.CleanURL(req), dpopProof,
		dpop.WithTokenValue(parts[1]),
	)
	if err != nil {
		return nil, errors.New("Invalid DPoP proof.")
	}

	// Prepare assertion
	assertion, err := cli.Assertion()
	if err != nil {
		return nil, fmt.Errorf("unable to prepare client authentication assertion: %w", err)
	}

	// Send introspection request to the issuer.
	t, err := cli.Introspect(ctx, assertion, parts[1])
	if err != nil {
		return nil, errors.New("Unable to get a successful token introspection response.")
	}
	switch {
	case t.Status != tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE:
		return nil, errors.New("Token is inactive.")
	case t.Confirmation == nil:
		return nil, errors.New("Request is using a DPoP with a token without PoP.")
	}

	// Compare token confirmation
	if !types.SecureCompareString(expectedJkt, t.Confirmation.Jkt) {
		return nil, errors.New("Invalid token.")
	}

	return &identity{
		Subject:  t.Metadata.Subject,
		ClientID: t.Metadata.ClientId,
	}, nil
}

func Authorizer(next http.Handler, intent string, cli client.Client) http.Handler {
	// Initialize the DPoP verifier.
	dpopVerifier := dpop.DefaultVerifier(inmemory.DPoPProofs(), jwt.EmbeddedKeyVerifier([]string{"ES384"}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			id      *identity
			authErr error
		)

		// Check if token is provided.
		authHeader := r.Header.Get("Authorization")
		switch {
		case authHeader == "":
			http.Error(w, "Authorization required.", http.StatusUnauthorized)
			return
		case strings.HasPrefix(strings.ToLower(authHeader), "bearer"):
			id, authErr = authenticateWithBearer(w, r, cli)
		case strings.HasPrefix(strings.ToLower(authHeader), "dpop"):
			id, authErr = authenticateWithDPoP(w, r, cli, dpopVerifier)
		default:
			http.Error(w, "Unsupported authorization method.", http.StatusBadRequest)
			return
		}

		// Authenticate the token
		if authErr != nil {
			log.Printf("auth error: %v", authErr)
			http.Error(w, "Unable to authenticate the request intent.", http.StatusUnauthorized)
			return
		}

		// Authorize the identity for intent
		if !can(id, intent) {
			http.Error(w, "Operation not allowed for this identity.", http.StatusForbidden)
			return
		}

		// Delegate to next handler.
		next.ServeHTTP(w, r)
	})
}
