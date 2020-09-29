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

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	discoveryv1 "zntr.io/solid/api/gen/go/oidc/discovery/v1"
	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/sdk/dpop"
	jwsreq "zntr.io/solid/pkg/sdk/jwsreq"
	"zntr.io/solid/pkg/sdk/pkce"
	"zntr.io/solid/pkg/sdk/types"

	"github.com/dchest/uniuri"
	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const bodyLimiterSize = 5 << 20 // 5 Mb

// HTTP creates an HTTP OIDC Client.
func HTTP(ctx context.Context, prover dpop.Prover, authorizationRequestEncoder jwsreq.AuthorizationEncoder, opts *Options) (Client, error) {

	// Initialize solid client
	c := &httpClient{
		opts:                        opts,
		prover:                      prover,
		authorizationRequestEncoder: authorizationRequestEncoder,
		httpClient:                  http.DefaultClient,
	}

	// Query server metadata endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/.well-known/oauth-authorization-server", opts.Issuer), nil)
	if err != nil {
		return nil, fmt.Errorf("unable to query server metadata: %w", err)
	}

	// Do the query
	response, err := c.httpClient.Do(req)
	if err != nil || response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to parse server metadata request: %w", err)
	}
	defer response.Body.Close()

	// Parse response
	if err := json.NewDecoder(response.Body).Decode(&c.serverMetadata); err != nil {
		return nil, fmt.Errorf("unable to decode server metadata: %w", err)
	}

	// Retrieve public keys
	if _, _, err := c.PublicKeys(ctx); err != nil {
		return nil, fmt.Errorf("unable to retrieve public keys: %w", err)
	}

	// No error
	return c, nil
}

// -----------------------------------------------------------------------------

type httpClient struct {
	opts                        *Options
	httpClient                  *http.Client
	prover                      dpop.Prover
	authorizationRequestEncoder jwsreq.AuthorizationEncoder
	jwks                        *jose.JSONWebKeySet
	jwksExpiration              uint64
	serverMetadata              *discoveryv1.ServerMetadata
}

// -----------------------------------------------------------------------------

func (c *httpClient) ClientID() string                            { return c.opts.ClientID }
func (c *httpClient) Audience() string                            { return c.opts.Audience }
func (c *httpClient) ServerMetadata() *discoveryv1.ServerMetadata { return c.serverMetadata }

// -----------------------------------------------------------------------------

func (c *httpClient) Assertion() (string, error) {
	var privateKey jose.JSONWebKey

	// Decode JWK
	err := json.Unmarshal(c.opts.JWK, &privateKey)
	if err != nil {
		return "", fmt.Errorf("unable to decode JWK: %w", err)
	}

	// Prepare a signer
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("unable to prepare signer: %w", err)
	}

	// Sign the assertion
	raw, err := jwt.Signed(sig).Claims(&privateJWTClaims{
		JTI:      uniuri.NewLen(8),
		Subject:  c.opts.ClientID,
		Issuer:   c.opts.ClientID,
		Audience: c.opts.Issuer,
		Expires:  uint64(time.Now().Add(30 * time.Second).Unix()),
		IssuedAt: uint64(time.Now().Unix()),
	}).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("unable to sign client assertion: %w", err)
	}

	// No error
	return raw, nil
}

func (c *httpClient) CreateRequestURI(ctx context.Context, assertion, state string) (*RequestURIResponse, error) {
	// Generate PKCE verifier
	pkceVerifier, pkceChallenge, err := pkce.CodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("unable to generate pkce proof: %w", err)
	}

	// Prepare PAR endpoint
	parURL, err := url.Parse(c.serverMetadata.PushedAuthorizationRequestEndpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to parse pushed_authorization_endpoint url: %w", err)
	}

	// Generate nonce
	nonce := uniuri.NewLen(12)

	// Prepare params
	params := url.Values{}

	// Client authentication
	params.Add("client_id", c.opts.ClientID)
	params.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	params.Add("client_assertion", assertion)

	// Prepare request
	ar := &corev1.AuthorizationRequest{
		State:               state,
		Audience:            c.opts.Audience,
		ResponseType:        "code",
		ResponseMode:        &wrapperspb.StringValue{Value: "query.jwt"},
		ClientId:            c.opts.ClientID,
		Nonce:               nonce,
		Scope:               fmt.Sprintf("openid %s", strings.Join(c.opts.Scopes, " ")),
		RedirectUri:         c.opts.RedirectURI,
		CodeChallenge:       pkceChallenge,
		CodeChallengeMethod: "S256",
	}

	// Check offline access requirements
	if types.StringArray(c.opts.Scopes).Contains(oidc.ScopeOfflineAccess) {
		ar.Prompt = &wrapperspb.StringValue{Value: "consent"}
	}

	// Authorization request encoder
	r, err := c.authorizationRequestEncoder.Encode(ctx, ar)
	if err != nil {
		return nil, fmt.Errorf("unable to encode request: %w", err)
	}

	// Assign request
	params.Add("request", r)

	// Assemble final url
	parURL.RawQuery = params.Encode()

	// Query PAR endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parURL.String(), strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("unable to prepare par request: %w", err)
	}

	// Set approppriate header value
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Prepare DPoP
	proof, err := c.prover.Prove(http.MethodPost, c.serverMetadata.PushedAuthorizationRequestEndpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to compute proof of possession: %w", err)
	}

	// Attach proof as header
	req.Header.Set("DPoP", proof)

	// Do the query
	response, err := c.httpClient.Do(req)
	if err != nil || response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unable to create authorization request: %w", err)
	}

	// Decode payload
	var jsonResponse jsonRequestURIResponse
	if err := json.NewDecoder(response.Body).Decode(&jsonResponse); err != nil {
		return nil, fmt.Errorf("unable to decode json response: %w", err)
	}
	defer response.Body.Close()

	// Check response
	if jsonResponse.Error != nil {
		return nil, fmt.Errorf("%s: %s", jsonResponse.Error.ErrorCode, jsonResponse.Error.ErrorDescription)
	}

	// No error
	return &RequestURIResponse{
		RequestURI:   jsonResponse.RequestURI,
		Nonce:        nonce,
		CodeVerifier: pkceVerifier,
	}, nil
}

func (c *httpClient) AuthenticationURL(ctx context.Context, requestURI string) (string, error) {
	// Parse authentication url endpoint
	authURL, err := url.Parse(c.serverMetadata.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("unable to parse authentication endpoint url: %w", err)
	}

	// Authorization request encoder
	request, err := c.authorizationRequestEncoder.Encode(ctx, &corev1.AuthorizationRequest{
		RequestUri: &wrapperspb.StringValue{Value: requestURI},
	})
	if err != nil {
		return "", fmt.Errorf("unable to encode request: %w", err)
	}

	// Generate parameters
	params := url.Values{}
	params.Add("client_id", c.opts.ClientID)
	params.Add("request", request)

	// Override url params
	authURL.RawQuery = params.Encode()

	// No error
	return authURL.String(), nil
}

// ExchangeCode uses authorization_code to retrieve the final tokens.
func (c *httpClient) ExchangeCode(ctx context.Context, assertion, code, pkceCodeVerifier string) (*oauth2.Token, error) {
	// Parse authentication url endpoint
	tokenURL, err := url.Parse(c.serverMetadata.TokenEndpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to parse token endpoint url: %w", err)
	}

	// Prepare parameters
	params := url.Values{}
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)
	params.Add("redirect_uri", c.opts.RedirectURI)
	params.Add("code_verifier", pkceCodeVerifier)
	params.Add("client_assertion", assertion)
	params.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

	// Assemble final url
	tokenURL.RawQuery = params.Encode()

	// Query token endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL.String(), strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("unable to prepare token request: %w", err)
	}

	// Set approppriate header value
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Prepare DPoP
	proof, err := c.prover.Prove(http.MethodPost, c.serverMetadata.TokenEndpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to compute proof of possession: %w", err)
	}

	// Attach proof as header
	req.Header.Set("DPoP", proof)

	// Do the query
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve token: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		var err corev1.Error

		// Decode json error
		if err := json.NewDecoder(io.LimitReader(response.Body, bodyLimiterSize)).Decode(&err); err != nil {
			return nil, fmt.Errorf("unable to decode json error for token retrieval request: %w", err)
		}

		return nil, fmt.Errorf("unable to request for token got %s, %s", err.Err, err.ErrorDescription)
	}

	// Decode payload
	var token oauth2.Token
	if err := json.NewDecoder(io.LimitReader(response.Body, bodyLimiterSize)).Decode(&token); err != nil {
		return nil, fmt.Errorf("unable to decode json response: %w", err)
	}

	// No error
	return &token, nil
}

func (c *httpClient) PublicKeys(ctx context.Context) (*jose.JSONWebKeySet, uint64, error) {
	// Check if keys are not cached and not expired
	if c.jwks != nil && c.jwksExpiration > uint64(time.Now().Unix()) {
		// Return cached public keys
		return c.jwks, c.jwksExpiration, nil
	}

	// Parse authentication url endpoint
	jwksURL, err := url.Parse(c.serverMetadata.JwksUri)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to parse jwks endpoint url: %w", err)
	}

	// Query token endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL.String(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to prepare jwks request: %w", err)
	}

	// Do the query
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to retrieve jwks: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		var err corev1.Error

		// Decode json error
		if err := json.NewDecoder(io.LimitReader(response.Body, bodyLimiterSize)).Decode(&err); err != nil {
			return nil, 0, fmt.Errorf("unable to decode json error for jwks retrieval request: %w", err)
		}

		return nil, 0, fmt.Errorf("unable to request for jwks got %s, %s", err.Err, err.ErrorDescription)
	}

	// Decode payload
	var jwks jsonJWKSResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, bodyLimiterSize)).Decode(&jwks); err != nil {
		return nil, 0, fmt.Errorf("unable to decode jwks response: %w", err)
	}

	// Check keys
	if len(jwks.Keys) == 0 {
		return nil, 0, fmt.Errorf("remote jwks doesn't contain keys")
	}

	// Check expiration
	if jwks.Expires > 0 && jwks.Expires < uint64(time.Now().Unix()) {
		return nil, 0, fmt.Errorf("remote jwks is expired")
	}

	// Set client values
	c.jwks = jwks.JSONWebKeySet
	c.jwksExpiration = jwks.Expires

	// No error
	return jwks.JSONWebKeySet, c.jwksExpiration, nil
}
