package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
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
	AuthTime *uint64
	Acr      *string
}

var permissions = map[string]map[string]types.StringArray{
	"timestamp:read": {
		"t8p9duw4n2klximkv3kagaud796ul67g": {
			"", // Allow client itself
		},
		"attestation-client": {
			"",
		},
	},
}

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
		return nil, errors.New("authorization header must be a 'Bearer' token")
	}

	// Prepare assertion
	assertion, err := cli.Assertion()
	if err != nil {
		return nil, fmt.Errorf("unable to prepare client authentication assertion: %w", err)
	}

	// Send introspection request to the issuer.
	t, err := cli.Introspect(ctx, assertion, parts[1])
	if err != nil {
		return nil, errors.New("unable to get a successful token introspection response")
	}
	switch {
	case t.Status != tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE:
		return nil, errors.New("token is inactive")
	case t.Confirmation != nil:
		return nil, errors.New("token requires a PoP proof to be used")
	}

	return &identity{
		Subject:  t.Metadata.Subject,
		ClientID: t.Metadata.ClientId,
		AuthTime: t.Metadata.AuthTime,
		Acr:      t.Metadata.Acr,
	}, nil
}

func authenticateWithDPoP(w http.ResponseWriter, req *http.Request, cli client.Client, dpopVerifier dpop.Verifier) (*identity, error) {
	ctx := req.Context()

	// Get token from request
	parts := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	if !strings.EqualFold(parts[0], "dpop") {
		return nil, errors.New("authorization header must be a 'DPoP' token")
	}

	// Check DPoP proof
	dpopProof := req.Header.Get("DPoP")

	// Validate dpop
	expectedJkt, err := dpopVerifier.Verify(ctx, req.Method, dpop.CleanURL(req), dpopProof,
		dpop.WithTokenValue(parts[1]),
	)
	if err != nil {
		return nil, errors.New("invalid DPoP proof")
	}

	// Prepare assertion
	assertion, err := cli.Assertion()
	if err != nil {
		return nil, fmt.Errorf("unable to prepare client authentication assertion: %w", err)
	}

	// Send introspection request to the issuer.
	t, err := cli.Introspect(ctx, assertion, parts[1])
	if err != nil {
		return nil, errors.New("unable to get a successful token introspection response")
	}
	switch {
	case t.Status != tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE:
		return nil, errors.New("token is inactive")
	case t.Confirmation == nil:
		return nil, errors.New("request is using a DPoP with a token without PoP")
	}

	// Compare token confirmation
	if !types.SecureCompareString(expectedJkt, t.Confirmation.Jkt) {
		return nil, errors.New("invalid token")
	}

	return &identity{
		Subject:  t.Metadata.Subject,
		ClientID: t.Metadata.ClientId,
		AuthTime: t.Metadata.AuthTime,
		Acr:      t.Metadata.Acr,
	}, nil
}

func Authorizer(next http.Handler, intent string, cli client.Client, acrValues types.StringArray, maxAuthAge uint64) http.Handler {
	// Initialize the DPoP verifier.
	dpopVerifier := dpop.DefaultVerifier(inmemory.DPoPProofs(), jwt.EmbeddedKeyVerifier([]jose.SignatureAlgorithm{jose.ES256, jose.ES384}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			id      *identity
			authErr error
		)

		// Check if token is provided.
		authHeader := r.Header.Get("Authorization")
		switch {
		case authHeader == "":
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_request", error_description="No access token provided in this request", resource="http://127.0.0.1:8085"`)
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
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="The access token provided is expired, revoked, malformed, or invalid for other reasons", resource="http://127.0.0.1:8085"`)
			log.Printf("auth error: %v", authErr)
			http.Error(w, "Unable to authenticate the request intent.", http.StatusUnauthorized)
			return
		}

		// Control authentication context
		if maxAuthAge > 0 && id.AuthTime != nil {
			if uint64(time.Now().Unix())-*id.AuthTime > maxAuthAge {
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication", error_description="More recent authentication is required", resource="http://127.0.0.1:8085"`+fmt.Sprintf(", max_age=%d", maxAuthAge))
				http.Error(w, "Unable to authenticate the request intent.", http.StatusUnauthorized)
				return
			}
		}
		if len(acrValues) > 0 && id.Acr != nil {
			if !acrValues.Contains(*id.Acr) {
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication", error_description="A different authentication level is required", resource="http://127.0.0.1:8085"`+fmt.Sprintf(", acr_values=%q", strings.Join(acrValues, " ")))
				http.Error(w, "Unable to authenticate the request intent.", http.StatusUnauthorized)
				return
			}
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
