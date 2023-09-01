package clientauthentication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/server/storage"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
)

// ClientAttestation authentication method.
func ClientAttestation(clients storage.ClientReader) AuthenticationProcessor {
	return &clientAttestationAuthentication{
		clients: clients,
	}
}

type clientAttestationConfirmationClaims struct {
	JWK *jose.JSONWebKey `json:"jwk"`
}

type clientAttestationClaims struct {
	Issuer       string                               `json:"iss"`
	Subject      string                               `json:"sub"`
	Expires      uint64                               `json:"exp"`
	NotBefore    uint64                               `json:"nbf"`
	IssuedAt     uint64                               `json:"iat"`
	JTI          string                               `json:"jti"`
	Confirmation *clientAttestationConfirmationClaims `json:"cnf,omitempty"`
}

type clientAttestationAuthentication struct {
	clients storage.ClientReader
}

type clientAttestationPOPClaims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Expires   uint64 `json:"exp"`
	NotBefore uint64 `json:"nbf"`
	IssuedAt  uint64 `json:"iat"`
	JTI       string `json:"jti"`
}

//nolint:funlen,gocyclo // to refactor
func (p *clientAttestationAuthentication) Authenticate(ctx context.Context, req *clientv1.AuthenticateRequest) (*clientv1.AuthenticateResponse, error) {
	res := &clientv1.AuthenticateResponse{}

	// Validate required fields for this authentication method
	if req.ClientAssertionType == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion_type must be defined")
	}
	if *req.ClientAssertionType != oidc.AssertionTypeJWTClientAttestation {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion_type must equals '%s', got '%s'", oidc.AssertionTypeJWTClientAttestation, *req.ClientAssertionType)
	}
	if req.ClientAssertion == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion must be defined")
	}
	if *req.ClientAssertion == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_assertion must not be empty")
	}

	// Split attestation and PoP
	assertions := strings.SplitN(*req.ClientAssertion, "~", 2)
	if len(assertions) != 2 {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, errors.New("invalid client assertion part count")
	}

	// Decode assertions without validation first
	clientPublicKey, err := p.validateClientAttestation(ctx, assertions[0])
	if err != nil {
		res.Error = rfcerrors.UnauthorizedClient().Build()
		return res, errors.New("invalid client attestation")
	}

	// Decode PoP
	rawPoP, err := jwt.ParseSigned(assertions[1])
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, errors.New("invalid client attestation PoP")
	}

	// Try to validate PoP with public key.
	var claims clientAttestationPOPClaims
	if err := rawPoP.Claims(clientPublicKey, &claims); err != nil {
		res.Error = rfcerrors.UnauthorizedClient().Build()
		return nil, fmt.Errorf("client attestation PoP is invalid: %w", err)
	}

	// Validate claims
	if claims.Issuer == "" || claims.Expires == 0 || claims.JTI == "" || claims.Audience == "" {
		return nil, fmt.Errorf("iss, exp, jti, aud are mandatory and not empty")
	}
	if claims.Expires < uint64(time.Now().Unix()) {
		return nil, fmt.Errorf("expired token")
	}
	if claims.NotBefore > uint64(time.Now().Unix()) {
		return nil, fmt.Errorf("not useable token")
	}

	// Check client in storage
	client, err := p.clients.Get(ctx, claims.Issuer)
	if err != nil {
		if err != storage.ErrNotFound {
			res.Error = rfcerrors.ServerError().Build()
			return res, fmt.Errorf("error during client retrieval: %w", err)
		}
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("client not found")
	}

	// Assign to response
	res.Client = client

	return res, nil
}

// -----------------------------------------------------------------------------

func (p *clientAttestationAuthentication) validateClientAttestation(ctx context.Context, clientAttestation string) (*jose.JSONWebKey, error) {
	// Parse attestation without cryptogrpahic verification first
	rawAttestation, err := jose.ParseSigned(clientAttestation)
	if err != nil {
		return nil, fmt.Errorf("client attestation is syntaxically invalid: %w", err)
	}

	// Retrieve payload claims
	var claims clientAttestationClaims
	if errDecode := json.Unmarshal(rawAttestation.UnsafePayloadWithoutVerification(), &claims); errDecode != nil {
		return nil, fmt.Errorf("unable to decode payload claims: %w", errDecode)
	}

	// Validate claims
	if claims.Issuer == "" || claims.Subject == "" || claims.Expires == 0 || claims.Confirmation == nil {
		return nil, fmt.Errorf("iss, sub, exp, cnf are mandatory and not empty")
	}
	if claims.Expires < uint64(time.Now().Unix()) {
		return nil, fmt.Errorf("expired token")
	}
	if claims.NotBefore > uint64(time.Now().Unix()) {
		return nil, fmt.Errorf("not useable token")
	}

	// Check client in storage
	client, err := p.clients.Get(ctx, claims.Issuer)
	if err != nil {
		if err != storage.ErrNotFound {
			return nil, fmt.Errorf("error during client retrieval: %w", err)
		}
		return nil, fmt.Errorf("client not found")
	}

	// Retrieve JWK associated to the client
	if len(client.Jwks) == 0 {
		return nil, fmt.Errorf("client jwks is nil")
	}

	// Parse JWKS
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(client.Jwks, &jwks); err != nil {
		return nil, fmt.Errorf("client jwks is invalid: %w", err)
	}

	// Try to validate assertion with one of keys
	if err := jwk.ValidateSignature(&jwks, rawAttestation); err != nil {
		return nil, fmt.Errorf("client assertion is invalid: %w", err)
	}

	// Extract client public key
	return claims.Confirmation.JWK, nil
}
