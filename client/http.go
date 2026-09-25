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

	gojwt "github.com/golang-jwt/jwt/v5"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	random "zntr.io/solid/sdk/random"
	"zntr.io/solid/sdk/token/jwt"
)

const bodyLimiterSize = 5 << 20 // 5 Mb

// HTTP creates an HTTP OIDC Client.
func HTTP(ctx context.Context, issuer string, opts *Options) (Client, error) {
	// Initialize solid client
	c := &httpClient{
		opts:       opts,
		issuer:     issuer,
		httpClient: http.DefaultClient,
	}

	// Query server metadata endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/.well-known/oauth-authorization-server", issuer), http.NoBody)
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

	// Validate the issuer value carried by the server metadata
	// (draft-ietf-oauth-security-topics-update-03 section 2.1.2.1: clients
	// MUST retrieve and validate the issuer identifier — an attacker
	// publishing or tampering metadata that claims a different issuer must
	// fail client construction). An absent issuer value is tolerated for
	// honest older authorization servers.
	if c.serverMetadata.Issuer != "" && c.serverMetadata.Issuer != issuer {
		return nil, fmt.Errorf("server metadata issuer %q does not match expected issuer %q", c.serverMetadata.Issuer, issuer)
	}

	// Retrieve public keys
	if _, _, err := c.PublicKeys(ctx); err != nil {
		return nil, fmt.Errorf("unable to retrieve public keys: %w", err)
	}

	// No error
	return c, nil
}

type httpClient struct {
	issuer         string
	opts           *Options
	httpClient     *http.Client
	jwks           jwk.Set
	jwksExpiration uint64
	serverMetadata *discoveryv1.ServerMetadata
}

// -----------------------------------------------------------------------------

func (c *httpClient) ClientID() string                            { return c.opts.ClientID }
func (c *httpClient) Audience() string                            { return c.opts.Audience }
func (c *httpClient) ServerMetadata() *discoveryv1.ServerMetadata { return c.serverMetadata }
func (c *httpClient) Issuer() string                              { return c.issuer }

// -----------------------------------------------------------------------------

func (c *httpClient) Assertion() (string, error) {
	// Decode JWK (AKP entries are decoded by the native ML-DSA parser)
	keySet, err := jwk.Parse(c.opts.JWK)
	if err != nil {
		return "", fmt.Errorf("unable to decode JWK: %w", err)
	}
	privateKey, ok := keySet.Key(0)
	if !ok {
		return "", fmt.Errorf("JWK document has no key")
	}

	// Resolve the signing method from the key algorithm.
	alg := "ES384"
	if a, ok := privateKey.Algorithm(); ok {
		alg = a.String()
	}
	method := gojwt.GetSigningMethod(alg)
	if method == nil {
		return "", fmt.Errorf("unsupported signing algorithm %q", alg)
	}

	// Materialize the signing key (unwraps AKP / ML-DSA keys)
	rawKey, err := jwt.MaterializeSigningKey(privateKey)
	if err != nil {
		return "", err
	}

	// Build the client assertion claims. Per draft-ietf-oauth-security-
	// topics-update-03 section 2.1.2.1, clients MUST use the authorization
	// server's issuer identifier as the sole audience value: the discovered
	// token_endpoint is never used as audience, so a forged token_endpoint
	// in attacker-controlled metadata cannot redirect assertions minted
	// for the honest AS.
	claims := gojwt.MapClaims{
		"jti": random.String(8),
		"sub": c.opts.ClientID,
		"iss": c.opts.ClientID,
		"aud": c.issuer,
		"exp": uint64(time.Now().Add(30 * time.Second).Unix()),
		"iat": uint64(time.Now().Unix()),
	}

	// Sign the assertion
	tok := gojwt.NewWithClaims(method, claims)
	tok.Header["typ"] = "JWT"
	raw, err := tok.SignedString(rawKey)
	if err != nil {
		return "", fmt.Errorf("unable to sign client assertion: %w", err)
	}

	// No error
	return raw, nil
}

func (c *httpClient) ClientCredentials(ctx context.Context, assertion string) (*Token, error) {
	// Parse authentication url endpoint
	tokenURL, err := url.Parse(c.serverMetadata.TokenEndpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to parse token endpoint url: %w", err)
	}

	// Prepare parameters
	params := url.Values{}
	params.Add("grant_type", "client_credentials")
	params.Add("client_assertion", assertion)
	params.Add("client_assertion_type", oidc.AssertionTypeJWTBearer)

	// Query token endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL.String(), strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("unable to prepare token request: %w", err)
	}

	// Set approppriate header value
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
	var token Token
	if err := json.NewDecoder(io.LimitReader(response.Body, bodyLimiterSize)).Decode(&token); err != nil {
		return nil, fmt.Errorf("unable to decode json response: %w", err)
	}

	// No error
	return &token, nil
}

func (c *httpClient) Introspect(ctx context.Context, assertion, token string) (*tokenv1.Token, error) {
	// Parse introspection url endpoint
	introspectionURL, err := url.Parse(c.serverMetadata.IntrospectionEndpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to parse introspection endpoint url: %w", err)
	}

	// Prepare parameters
	params := url.Values{}
	params.Add("token", token)
	params.Add("client_assertion", assertion)
	params.Add("client_assertion_type", oidc.AssertionTypeJWTBearer)

	// Query token endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, introspectionURL.String(), strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("unable to prepare introspection request: %w", err)
	}

	// Set approppriate header value
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Do the query
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve instorspection response: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		var err corev1.Error

		// Decode json error
		if err := json.NewDecoder(io.LimitReader(response.Body, bodyLimiterSize)).Decode(&err); err != nil {
			return nil, fmt.Errorf("unable to decode json error for token introspection request: %w", err)
		}

		return nil, fmt.Errorf("unable to request for token introspection got %s, %s", err.Err, err.ErrorDescription)
	}
	// Read the payload once: the proto TokenMeta custom unmarshaler would
	// consume the whole JSON object when embedded in a struct, shadowing
	// sibling fields; decode the parts separately instead.
	rawBody, err := io.ReadAll(io.LimitReader(response.Body, bodyLimiterSize))
	if err != nil {
		return nil, fmt.Errorf("unable to read json response: %w", err)
	}
	var t jsonTokenIntrospectionResponse
	if err := json.Unmarshal(rawBody, &t); err != nil {
		return nil, fmt.Errorf("unable to decode json response: %w", err)
	}

	tokenStatus := tokenv1.TokenStatus_TOKEN_STATUS_UNSPECIFIED
	if t.Active {
		tokenStatus = tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE
	}

	var meta tokenv1.TokenMeta
	if err := json.Unmarshal(rawBody, &meta); err != nil {
		return nil, fmt.Errorf("unable to decode json response: %w", err)
	}
	var confirmationWrapper struct {
		Confirmation *tokenv1.TokenConfirmation `json:"cnf"`
	}
	if err := json.Unmarshal(rawBody, &confirmationWrapper); err != nil {
		return nil, fmt.Errorf("unable to decode json response: %w", err)
	}
	// Return token info
	return &tokenv1.Token{
		Issuer:       c.issuer,
		Status:       tokenStatus,
		Confirmation: confirmationWrapper.Confirmation,
		Metadata:     &meta,
		Value:        token,
	}, nil
}

func (c *httpClient) PublicKeys(ctx context.Context) (keys jwk.Set, expiresAt uint64, err error) {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL.String(), http.NoBody)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to prepare jwks request: %w", err)
	}

	// Do the query
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to retrieve jwks: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		var err corev1.Error

		// Decode json error
		if err := json.NewDecoder(io.LimitReader(response.Body, bodyLimiterSize)).Decode(&err); err != nil {
			return nil, 0, fmt.Errorf("unable to decode json error for jwks retrieval request: %w", err)
		}

		return nil, 0, fmt.Errorf("unable to request for jwks got %s, %s", err.Err, err.ErrorDescription)
	}

	// Decode payload: parse the JWKS with the tolerant parser (AKP entries
	// are decoded natively; standard entries stay strictly validated), and
	// pick up the exp member separately.
	body, err := io.ReadAll(io.LimitReader(response.Body, bodyLimiterSize))
	if err != nil {
		return nil, 0, fmt.Errorf("unable to read jwks response: %w", err)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to decode jwks response: %w", err)
	}
	var probe struct {
		Expires uint64 `json:"exp"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, 0, fmt.Errorf("unable to decode jwks response: %w", err)
	}
	jwks := jsonJWKSResponse{Set: set, Expires: probe.Expires}

	// Check keys
	if jwks.Set == nil || jwks.Len() == 0 {
		return nil, 0, fmt.Errorf("remote jwks doesn't contain keys")
	}

	// Check expiration
	if jwks.Expires > 0 && jwks.Expires < uint64(time.Now().Unix()) {
		return nil, 0, fmt.Errorf("remote jwks is expired")
	}

	// Set client values
	c.jwks = jwks.Set
	c.jwksExpiration = jwks.Expires

	// No error
	return c.jwks, c.jwksExpiration, nil
}
