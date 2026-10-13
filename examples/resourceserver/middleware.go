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
	Subject              string
	ClientID             string
	AuthTime             *uint64
	Acr                  *string
	Scope                string
	Audience             string
	AuthorizationDetails []*tokenv1.AuthorizationDetail
}

// resourceMetadataURI is this resource server's RFC 8707 resource
// identifier: the audience every accepted access token must carry.
const resourceMetadataURI = "http://127.0.0.1:8085"

var permissions = map[string]map[string]types.StringArray{
	"timestamp:read": {
		"t8p9duw4n2klximkv3kagaud796ul67g": {
			"", // No subject restriction (see can())
		},
		"attestation-client": {
			"",
		},
		// The MCP tool server (examples/mcpserver): calls through its
		// second-hop exchanged token (T5, client_id = the MCP server,
		// RFC 8693 section 4.3); the mcpToolAccess gate below evaluates
		// the carried mcp_tools authorization detail before access is
		// granted.
		"https://mcp.example.org/server": {
			"",
		},
	},
}

// mcpToolAccess pins the MCP tool server's tool-grant requirement: the
// presented token must carry an mcp_tools authorization detail for this
// resource whose actions include the requested intent (RFC 9396 section 5,
// evaluated by the resource server — the remote MCP service makes the
// authorization decision; the AS carries the entries without evaluating
// them).
var mcpToolAccess = map[string]struct {
	Type      string
	Locations []string
}{
	"https://mcp.example.org/server": {Type: "mcp_tools", Locations: []string{"http://127.0.0.1:8085"}},
}

// hasToolGrant reports whether the identity's token carries the matching
// mcp_tools authorization detail for the requested intent.
func hasToolGrant(id *identity, intent string) bool {
	req, ok := mcpToolAccess[id.ClientID]
	if !ok {
		return false
	}
	for _, d := range id.AuthorizationDetails {
		if d == nil || d.Type != req.Type {
			continue
		}
		if types.StringArray(d.Locations).Contains(req.Locations[0]) &&
			types.StringArray(d.Actions).Contains(intent) {
			return true
		}
	}
	return false
}

func can(id *identity, intent string) bool {
	// Check permission request
	clients, ok := permissions[intent]
	if !ok {
		return false
	}

	// Check subject permission. An empty entry ("") is the demo's
	// wildcard: no subject restriction — the client allowlist plus the
	// tool-grant, audience and scope gates below carry the authorization
	// decision. Delegated tokens carry the end-user subject (RFC 8693
	// section 4.1 sub), self-acting machine tokens the client id; a
	// fixed subject list cannot express either with pairwise subjects.
	subjects, ok := clients[id.ClientID]
	if !ok {
		return false
	}
	if !subjects.Contains("") && !subjects.Contains(id.Subject) {
		return false
	}

	// MCP tool-grant evaluation: clients pinned in mcpToolAccess must
	// present a token carrying the matching authorization detail.
	if _, ok := mcpToolAccess[id.ClientID]; ok && !hasToolGrant(id, intent) {
		return false
	}

	return true
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
		Scope:    t.Metadata.Scope,
		Audience: t.Metadata.Audience,
		// RFC 9396: the carried authorization details are evaluated by
		// this resource server (the AS transport-only pass-through).
		AuthorizationDetails: t.Metadata.AuthorizationDetails,
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
		Scope:    t.Metadata.Scope,
		Audience: t.Metadata.Audience,
		// RFC 9396: the carried authorization details are evaluated by
		// this resource server (the AS transport-only pass-through).
		AuthorizationDetails: t.Metadata.AuthorizationDetails,
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

		if !checkTokenEligibility(w, id, intent, acrValues, maxAuthAge) {
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

// checkTokenEligibility enforces the token-level requirements on the
// authenticated identity — audience (RFC 8707), scope (RFC 6749 section
// 3.3), authentication age (max_age) and authentication context (RFC
// 9470; a required ACR with a token carrying none fails closed) — writing
// the RFC 6750 challenge and returning false on the first violation.
func checkTokenEligibility(w http.ResponseWriter, id *identity, intent string, acrValues types.StringArray, maxAuthAge uint64) bool {
	// RFC 8707: the token must be audience-restricted to this resource
	// server — a token minted for another RS, presented here by an
	// allowlisted client, is not a valid credential for the intent.
	if id.Audience != "" && !types.SecureCompareString(id.Audience, resourceMetadataURI) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="The access token provided is expired, revoked, malformed, or invalid for other reasons", resource="`+resourceMetadataURI+`", resource_metadata="`+resourceMetadataURI+`/.well-known/oauth-protected-resource"`)
		http.Error(w, "Unable to authenticate the request intent.", http.StatusUnauthorized)
		return false
	}

	// RFC 6749 section 3.3: the token must carry the scope the intent
	// requires — a token lacking the intent scope is authorized for
	// nothing here, whatever the client allowlist says.
	if id.Scope != "" && !types.StringArray(strings.Fields(id.Scope)).Contains(intent) {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", error_description="The access token does not carry the scope required by the intent", resource="`+resourceMetadataURI+`", resource_metadata="`+resourceMetadataURI+`/.well-known/oauth-protected-resource"`+fmt.Sprintf(", scope=%q", intent))
		http.Error(w, "Operation not allowed for this identity.", http.StatusForbidden)
		return false
	}

	// Control authentication context
	if maxAuthAge > 0 && id.AuthTime != nil {
		if uint64(time.Now().Unix())-*id.AuthTime > maxAuthAge { //nolint:gosec // unix time is non-negative
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication", error_description="More recent authentication is required", resource="`+resourceMetadataURI+`", resource_metadata="`+resourceMetadataURI+`/.well-known/oauth-protected-resource"`+fmt.Sprintf(", max_age=%d", maxAuthAge))
			http.Error(w, "Unable to authenticate the request intent.", http.StatusUnauthorized)
			return false
		}
	}
	// RFC 9470: when the RS requires an ACR, a token without any ACR does
	// not satisfy the requirement — nil fails closed.
	if len(acrValues) > 0 && id.Acr == nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication", error_description="The access token does not carry an authentication context class", resource="`+resourceMetadataURI+`", resource_metadata="`+resourceMetadataURI+`/.well-known/oauth-protected-resource"`+fmt.Sprintf(", acr_values=%q", strings.Join(acrValues, " ")))
		http.Error(w, "Unable to authenticate the request intent.", http.StatusUnauthorized)
		return false
	}
	if id.Acr != nil && !acrValues.Contains(*id.Acr) {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication", error_description="A different authentication level is required", resource="`+resourceMetadataURI+`", resource_metadata="`+resourceMetadataURI+`/.well-known/oauth-protected-resource"`+fmt.Sprintf(", acr_values=%q", strings.Join(acrValues, " ")))
		http.Error(w, "Unable to authenticate the request intent.", http.StatusUnauthorized)
		return false
	}
	return true
}
