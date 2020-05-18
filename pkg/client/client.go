package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.zenithar.org/solid/pkg/pkce"

	"github.com/dchest/uniuri"
	"github.com/square/go-jose/v3"
	jwt "github.com/square/go-jose/v3/jwt"
	"golang.org/x/oauth2"
)

// Client describes OIDC client contract.
type Client interface {
	Assertion() (string, error)
	CreateRequestURI(ctx context.Context, assertion, state string) (*RequestURIResponse, error)
	AuthenticationURL(requestURI string) (string, error)
	ExchangeCode(ctx context.Context, assertion string, authorizationCode string, pkceCodeVerifier string) (*oauth2.Token, error)
}

// New oidc client.
func New(opts Options) Client {
	return &client{
		opts:                               opts,
		httpClient:                         http.DefaultClient,
		authorizationEndpoint:              fmt.Sprintf("%s/authorize", opts.Issuer),
		pushedAuthorizationRequestEndpoint: fmt.Sprintf("%s/par", opts.Issuer),
		tokenEndpoint:                      fmt.Sprintf("%s/token", opts.Issuer),
	}
}

// Options defines client options
type Options struct {
	Issuer      string
	Audience    string
	ClientID    string
	RedirectURI string
	Scopes      []string
	JWK         []byte
}

type client struct {
	opts       Options
	httpClient *http.Client
	// Endpoints
	authorizationEndpoint              string
	pushedAuthorizationRequestEndpoint string
	tokenEndpoint                      string
}

// -----------------------------------------------------------------------------

func (c *client) Assertion() (string, error) {
	var privateKey jose.JSONWebKey

	// Decode JWK
	err := json.Unmarshal(c.opts.JWK, &privateKey)
	if err != nil {
		return "", fmt.Errorf("unable to decode JWK: %w", err)
	}

	// Prepare a signer
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT"))
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

func (c *client) CreateRequestURI(ctx context.Context, assertion, state string) (*RequestURIResponse, error) {
	// Generate PKCE verifier
	pkceVerifier, pkceChallenge, err := pkce.CodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("unable to generate pkce proof: %w", err)
	}

	// Prepare PAR endpoint
	parURL, err := url.Parse(c.pushedAuthorizationRequestEndpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to parse pushed_authorization_endpoint url: %w", err)
	}

	// Generate nonce
	nonce := uniuri.NewLen(12)

	// Prepare params
	params := url.Values{}
	params.Add("state", state)
	params.Add("audience", c.opts.Audience)
	params.Add("response_type", "code")
	params.Add("client_id", c.opts.ClientID)
	params.Add("nonce", nonce)
	params.Add("scope", fmt.Sprintf("openid %s", strings.Join(c.opts.Scopes, " ")))
	params.Add("redirect_uri", c.opts.RedirectURI)
	params.Add("code_challenge", pkceChallenge)
	params.Add("code_challenge_method", "S256")
	params.Add("client_assertion", assertion)
	params.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

	// Assemple final url
	parURL.RawQuery = params.Encode()

	// Query PAR endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parURL.String(), strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("unable to prepare par request: %w", err)
	}

	// Set approppriate header value
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Do the query
	response, err := c.httpClient.Do(req)
	if err != nil || response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unable to create authorization request")
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

func (c *client) AuthenticationURL(requestURI string) (string, error) {
	// Parse authentication url endpoint
	authURL, err := url.Parse(c.authorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("unable to parse authentication endpoint url: %w", err)
	}

	// Generate parameters
	params := url.Values{}
	params.Add("request_uri", requestURI)

	// Override url params
	authURL.RawQuery = params.Encode()

	// No error
	return authURL.String(), nil
}

// ExchangeCode uses authorization_code to retrieve the final tokens.
func (c *client) ExchangeCode(ctx context.Context, assertion, code, pkceCodeVerifier string) (*oauth2.Token, error) {
	// Parse authentication url endpoint
	tokenURL, err := url.Parse(c.tokenEndpoint)
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

	// Assemple final url
	tokenURL.RawQuery = params.Encode()

	// Query PAR endpoint
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
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to request for token")
	}

	// Decode payload
	var token oauth2.Token
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("unable to decode json response: %w", err)
	}
	defer response.Body.Close()

	// No error
	return &token, nil
}
