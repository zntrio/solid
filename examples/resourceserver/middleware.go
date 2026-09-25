// Licensed to SolID under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. SolID licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/client"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
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

func authenticateWithBearer(req *http.Request, cli client.Client) (*identity, error) {
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
	case t.Confirmation != nil && t.Confirmation.Jkt != "":
		return nil, errors.New("token requires a PoP proof to be used")
	case t.Confirmation != nil && t.Confirmation.X5TS256 != "":
		// RFC 8705 section 3: a certificate-bound token is only usable
		// over mutual TLS with the exact bound certificate.
		if req.TLS == nil || !token.CertificateBound(t.Confirmation, req.TLS.PeerCertificates) {
			return nil, errors.New("invalid token: certificate binding mismatch")
		}
	}

	return &identity{
		Subject:  t.Metadata.Subject,
		ClientID: t.Metadata.ClientId,
		AuthTime: t.Metadata.AuthTime,
		Acr:      t.Metadata.Acr,
	}, nil
}

func authenticateWithDPoP(req *http.Request, cli client.Client, dpopVerifier dpop.Verifier) (*identity, error) {
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

	// RFC 8705 section 3: when the DPoP-bound token is also
	// certificate-bound, both proofs are required.
	if t.Confirmation.X5TS256 != "" {
		if req.TLS == nil || !token.CertificateBound(t.Confirmation, req.TLS.PeerCertificates) {
			return nil, errors.New("invalid token: certificate binding mismatch")
		}
	}

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
	dpopVerifier := dpop.DefaultVerifier(inmemory.DPoPProofs(), jwt.EmbeddedKeyVerifier([]string{jwk.MLDSA65}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			id      *identity
			authErr error
		)

		// Check if token is provided.
		authHeader := r.Header.Get("Authorization")
		switch {
		case authHeader == "":
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_request", error_description="No access token provided in this request", resource="http://127.0.0.1:8085", resource_metadata="http://127.0.0.1:8085/.well-known/oauth-protected-resource"`)
			http.Error(w, "Authorization required.", http.StatusUnauthorized)
			return
		case strings.HasPrefix(strings.ToLower(authHeader), "bearer"):
			id, authErr = authenticateWithBearer(r, cli)
		case strings.HasPrefix(strings.ToLower(authHeader), "dpop"):
			id, authErr = authenticateWithDPoP(r, cli, dpopVerifier)
		default:
			http.Error(w, "Unsupported authorization method.", http.StatusBadRequest)
			return
		}

		// Authenticate the token
		if authErr != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="The access token provided is expired, revoked, malformed, or invalid for other reasons", resource="http://127.0.0.1:8085", resource_metadata="http://127.0.0.1:8085/.well-known/oauth-protected-resource"`)
			log.Printf("auth error: %v", authErr)
			http.Error(w, "Unable to authenticate the request intent.", http.StatusUnauthorized)
			return
		}

		// Control authentication context
		if maxAuthAge > 0 && id.AuthTime != nil {
			if uint64(time.Now().Unix())-*id.AuthTime > maxAuthAge { //nolint:gosec // unix time is non-negative
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication", error_description="More recent authentication is required", resource="http://127.0.0.1:8085", resource_metadata="http://127.0.0.1:8085/.well-known/oauth-protected-resource"`+fmt.Sprintf(", max_age=%d", maxAuthAge))
				http.Error(w, "Unable to authenticate the request intent.", http.StatusUnauthorized)
				return
			}
		}
		if len(acrValues) > 0 && id.Acr != nil {
			if !acrValues.Contains(*id.Acr) {
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication", error_description="A different authentication level is required", resource="http://127.0.0.1:8085", resource_metadata="http://127.0.0.1:8085/.well-known/oauth-protected-resource"`+fmt.Sprintf(", acr_values=%q", strings.Join(acrValues, " ")))
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
