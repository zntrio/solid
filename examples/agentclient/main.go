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

// agentclient demonstrates an AI agent acting on behalf of a user against
// a remote MCP-style resource server through OAuth token exchange
// (RFC 8693):
//
//  1. the agent — a Client ID Metadata Document client
//     (draft-ietf-oauth-client-id-metadata-document) identified by
//     https://agent.example.org/ai-agent — pushes a signed request object
//     (JAR, RFC 9101) to the PAR endpoint (RFC 9126), DPoP-proved
//     (RFC 9449);
//  2. the user authenticates at the authorization endpoint consuming the
//     PAR request_uri (Basic hello/world — the demo stand-in for the
//     resource-owner login surface), and the response arrives as a JARM
//     query.jwt (RFC 9447) redirect;
//  3. the agent redeems the authorization code (PKCE + DPoP) for a
//     key-bound subject access token;
//  4. the agent performs a token exchange carrying authorization_details
//     (RFC 9396) for the remote MCP service, with its own
//     client_credentials token as actor_token (RFC 8693 section 4.4
//     delegation: the exchanged token records the agent in the act
//     chain). The AS applies mocked processing: the requested entries are
//     carried verbatim — the AS enforces no consent narrowing;
//  5. the agent calls the resource server with the exchanged token; the
//     RS introspects it and evaluates the carried mcp_tools
//     authorization detail — the resource server is the authorization
//     authority for MCP tool access.
//
// Prerequisites: the example authorization server and resource server are
// running (go run ./examples/authorizationserver, go run
// ./examples/resourceserver).
package main

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/client"
	"zntr.io/solid/examples/authorizationserver/cimddemo"
	exampleenv "zntr.io/solid/examples/internal/exampleenv"
	"zntr.io/solid/examples/internal/flowlog"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/jarm"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/jwsreq"
	"zntr.io/solid/sdk/pkce"
	random "zntr.io/solid/sdk/random"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/sdtoken/sdjwt"
	"zntr.io/solid/sdk/token/jwt"
)

const (
	// redirectURI is the agent's loopback redirect endpoint; no listener
	// is needed, the demo captures the 302 Location directly.
	redirectURI = "http://127.0.0.1:8100/callback"

	// mcpServerURI is the MCP tool server (examples/mcpserver): the
	// RFC 8707 resource indicator of the first token-exchange hop and
	// the location the mcp_tools detail is scoped to.
	mcpServerURI = "http://127.0.0.1:8090"

	// backendResourceURI is the backend resource server
	// (examples/resourceserver): the audience of the MCP server's
	// second token-exchange hop; the user consents to the backend
	// mcp_tools detail at PAR so the re-delegation's subset request
	// passes.
	backendResourceURI = "http://127.0.0.1:8085"

	// mcpToolDetail is the first-hop authorization_details entry
	// (RFC 9396): the mcp_tools grant for the tool invocation on the
	// MCP server.
	mcpToolDetail = `{"type":"mcp_tools","locations":["http://127.0.0.1:8090"],"actions":["get_signed_timestamp"]}`

	// backendToolDetail is the backend authorization_details entry
	// (RFC 9396): the mcp_tools grant the MCP server re-delegates
	// with (a subset of the user's consented set).
	backendToolDetail = `{"type":"mcp_tools","locations":["http://127.0.0.1:8085"],"actions":["timestamp:read"]}`
)

// flowlogClient prints the protocol flow (request and response) for every
// exchange in the demo.
var flowlogClient = flowlog.New()

// noRedirectClient shares the flowlog transport but never follows the 302
// of the authorization endpoint: the JARM response is captured from the
// Location header.
var noRedirectClient = &http.Client{
	Transport: flowlogClient.Transport,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// issuer is the AS issuer identifier, overridable with SOLID_EXAMPLE_ISSUER.
var issuer = exampleenv.Or("SOLID_EXAMPLE_ISSUER", "http://127.0.0.1:8080")

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "agent demo failed:", err)
		os.Exit(1)
	}
}

//nolint:gocyclo,funlen // linear demo flow; each step is a protocol phase
func run() error {
	ctx := context.Background()

	// Rebuild the agent JWK (AKP, ML-DSA-65) from the published fixture
	// seed: the same private key drives the client assertions, the JAR
	// request-object signature and the DPoP proofs (deviceclient
	// precedent); the derived public key matches the JWKS published in
	// the agent's Client ID Metadata Document.
	seed, err := base64.RawURLEncoding.DecodeString(cimddemo.AgentClientSeedB64)
	if err != nil {
		return fmt.Errorf("unable to decode agent seed: %w", err)
	}
	jwkDoc := fmt.Sprintf(`{"alg":"ML-DSA-65","d":%q,"kid":%q,"kty":"AKP","pub":%q}`,
		base64.RawURLEncoding.EncodeToString(seed), cimddemo.AgentClientIdentifierURL, cimddemo.AgentClientPubB64)

	// Create the OIDC client for the CIMD identifier: discovery resolves
	// the endpoints, assertions are minted with the fixture key.
	oidcClient, err := client.HTTP(ctx, issuer, &client.Options{
		ClientID:   cimddemo.AgentClientIdentifierURL,
		JWK:        []byte(jwkDoc),
		HTTPClient: flowlogClient,
	})
	if err != nil {
		return fmt.Errorf("unable to create oidc client: %w", err)
	}
	md := oidcClient.ServerMetadata()
	if md.AuthorizationEndpoint == "" || md.TokenEndpoint == "" {
		return fmt.Errorf("server metadata does not advertise the authorization endpoints")
	}

	// DPoP prover over the same ML-DSA key (RFC 9449): every PAR, token
	// and resource call is proved with the agent key; the subject token
	// is minted bound to its thumbprint.
	keySet, err := jwk.Parse([]byte(jwkDoc))
	if err != nil {
		return fmt.Errorf("unable to decode agent key: %w", err)
	}
	key, ok := keySet.Key(0)
	if !ok {
		return fmt.Errorf("agent JWK has no key")
	}
	prover := dpop.DefaultProver(jwt.DPoPSigner("ML-DSA-65", func(context.Context) (jwk.Key, error) {
		return key, nil
	}))
	jkt, err := keyThumbprint(jwkDoc)
	if err != nil {
		return fmt.Errorf("unable to compute DPoP key thumbprint: %w", err)
	}
	fmt.Println("→ DPoP key thumbprint (dpop_jkt):", jkt)

	// PKCE (RFC 7636) and the request state/nonce.
	verifier, challenge, err := pkce.CodeVerifier()
	if err != nil {
		return fmt.Errorf("unable to generate PKCE pair: %w", err)
	}
	state := random.String(43)
	nonce := random.String(16)

	// 1. JAR request object (RFC 9101), signed with the agent key.
	requestObject, err := signedRequest(issuer, state, nonce, challenge, jkt)
	if err != nil {
		return fmt.Errorf("unable to sign request object: %w", err)
	}

	// 2. PAR (RFC 9126): a fresh client assertion (each jti single-use,
	// RFC 7523) and a DPoP proof (mandatory at the PAR endpoint).
	parAssertion, err := oidcClient.Assertion()
	if err != nil {
		return fmt.Errorf("unable to mint client assertion: %w", err)
	}
	parProof, err := prover.Prove(http.MethodPost, issuer+"/par")
	if err != nil {
		return fmt.Errorf("unable to mint DPoP proof: %w", err)
	}
	requestURI, err := pushAuthorizationRequest(ctx, issuer, parAssertion, parProof, requestObject)
	if err != nil {
		return err
	}
	fmt.Println("← request_uri:", requestURI)

	// 3. User authentication at the authorization endpoint: the request_uri
	// consumes the pushed request. In a real deployment the user's
	// browser follows the redirect; the demo performs the front-channel
	// leg directly with the Basic fixture standing in for the
	// resource-owner login, and captures the 302 JARM response.
	fmt.Println("→ user approval (mocked): GET /authorize with Basic hello:world")
	responseJWT, err := authorize(ctx, issuer, cimddemo.AgentClientIdentifierURL, requestURI)
	if err != nil {
		return err
	}

	// 4. Verify the JARM response (RFC 9447 query.jwt) with the AS keys.
	decoder := jarm.Decoder(issuer, jwt.DefaultVerifier(func(context.Context) (jwk.Set, error) {
		asKeys, _, errKeys := oidcClient.PublicKeys(ctx)
		return asKeys, errKeys
	}, []string{"ML-DSA-65"}))
	jarmRes, err := decoder.Decode(ctx, cimddemo.AgentClientIdentifierURL, responseJWT)
	if err != nil {
		return fmt.Errorf("unable to verify JARM response: %w", err)
	}
	if jarmRes.State != state {
		return fmt.Errorf("state mismatch: got %q, want %q", jarmRes.State, state)
	}
	if jarmRes.Code == "" {
		return fmt.Errorf("authorization response carries no code (error: %s)", jarmRes.GetError().GetError())
	}
	fmt.Println("← authorization code (JARM verified, state matches):", jarmRes.Code[:16]+"…")

	// 5. Redeem the code (PKCE + DPoP proof of the bound key).
	redeemAssertion, err := oidcClient.Assertion()
	if err != nil {
		return fmt.Errorf("unable to mint client assertion: %w", err)
	}
	redeemProof, err := prover.Prove(http.MethodPost, md.TokenEndpoint)
	if err != nil {
		return fmt.Errorf("unable to mint DPoP proof: %w", err)
	}
	subjectRes, err := redeemCode(ctx, md, redeemAssertion, redeemProof, jarmRes.Code, verifier)
	if err != nil {
		return err
	}
	fmt.Println("← subject access token (token_type:", subjectRes.TokenType+")")

	// D-12.1: the reference AS issues the opt-in SD-JWT id_token with
	// the code-flow tokens (scope includes openid). As the relying
	// party, verify it: signature against the AS keys, typ id+jwt,
	// aud = this client, nonce = the authorization-request nonce, and
	// process the disclosures to recover the user claims (digests only
	// in the token itself).
	if subjectRes.IDToken != "" {
		idVerifier, errBuild := sdjwt.NewAccessTokenVerifier(sdtoken.IDTokenProfile, sdjwt.Deps{
			IssuerKeys: func(context.Context) (jwk.Set, error) {
				asKeys, _, errKeys := oidcClient.PublicKeys(ctx)
				return asKeys, errKeys
			},
		},
			// OIDC Core section 2: the audience of an id_token is the
			// client_id of the relying party.
			sdtoken.WithAudience(cimddemo.AgentClientIdentifierURL),
			// OIDC Core id_tokens carry no key binding.
			sdtoken.WithOptionalKeyBinding(),
		)
		if errBuild != nil {
			return fmt.Errorf("unable to build id_token verifier: %w", errBuild)
		}
		idClaims, errVerify := idVerifier.Verify(ctx, subjectRes.IDToken, subjectRes.IDTokenDisclosures, "", nil)
		if errVerify != nil {
			return fmt.Errorf("unable to verify the id_token: %w", errVerify)
		}
		if echo, _ := idClaims["nonce"].(string); echo != nonce {
			return fmt.Errorf("id_token nonce mismatch: got %q, want %q", echo, nonce)
		}
		fmt.Printf("← id_token (SD id+jwt, D-12.1): iss=%s sub=%s aud=%s nonce echoed\n",
			idClaims["iss"], idClaims["sub"], idClaims["aud"])
		email, _ := idClaims["email"].(string)
		name, _ := idClaims["name"].(string)
		fmt.Printf("← disclosed user claims (from id_token_disclosures): email=%q name=%q\n", email, name)
	}

	// The subject token nbf is iat+1: wait for usability.
	time.Sleep(1 * time.Second)

	// 6. Actor token: the agent's own client_credentials token (RFC 8693
	// section 4.4 delegation — the exchanged token records the agent in
	// the act chain).
	actorAssertion, err := oidcClient.Assertion()
	if err != nil {
		return fmt.Errorf("unable to mint client assertion: %w", err)
	}
	// DPoP-proved like every other token request: the AS resolves the
	// agent's CIMD document with the metadata policy defaulting
	// dpop_bound_access_tokens (OpenID Federation 1.0 section 6.1.3.1
	// default operator), so the client_credentials mint is sender-bound
	// to the agent key.
	actorProof, err := prover.Prove(http.MethodPost, md.TokenEndpoint)
	if err != nil {
		return fmt.Errorf("unable to mint DPoP proof: %w", err)
	}
	actorRes, err := clientCredentials(ctx, md, actorAssertion, actorProof)
	if err != nil {
		return err
	}
	fmt.Println("← actor token (client_credentials):", actorRes.AccessToken[:16]+"…")

	// 7. First token-exchange hop (RFC 8693): subject = the user's token,
	// actor = the agent's token, resource = the MCP tool server. The
	// exchange requests BOTH consented mcp_tools entries — the MCP
	// server's re-delegation needs the backend entry as a subset of the
	// subject token it exchanges. The AS delegation policy mints
	// may_act = [the MCP server] on the exchanged token (T3). The DPoP
	// proof of the same bound key: the exchange rejects proof-key swaps
	// (RFC 9449 section 8).
	exchangeAssertion, err := oidcClient.Assertion()
	if err != nil {
		return fmt.Errorf("unable to mint client assertion: %w", err)
	}
	exchangeProof, err := prover.Prove(http.MethodPost, md.TokenEndpoint)
	if err != nil {
		return fmt.Errorf("unable to mint DPoP proof: %w", err)
	}
	exRes, err := tokenExchange(ctx, md, exchangeAssertion, exchangeProof, subjectRes.AccessToken, actorRes.AccessToken)
	if err != nil {
		return err
	}
	fmt.Printf("← delegated token T3 (token_type: %s, expires_in: %ds)\n", exRes.TokenType, exRes.ExpiresIn)
	fmt.Println("← authorization_details echoed (RFC 9396 §7):", exRes.AuthorizationDetails)

	// 8. Invoke the get_signed_timestamp tool on the MCP server with
	// T3, proved with the same bound key. The MCP server introspects
	// T3, then re-delegates (may_act) to the backend resource server
	// and relays the signed timestamp as the tool result. T3 lives 60
	// seconds: no delay before the tool call.
	toolProof, err := prover.Prove(http.MethodPost, mcpServerURI+"/tools/get_signed_timestamp/invoke", dpop.WithTokenValue(exRes.AccessToken))
	if err != nil {
		return fmt.Errorf("unable to mint DPoP proof: %w", err)
	}
	timestampRaw, err := invokeTool(ctx, exRes.AccessToken, toolProof)
	if err != nil {
		return err
	}
	fmt.Println("← tool result (signed timestamp, relayed through the MCP server):")
	fmt.Println(string(timestampRaw))

	// 9. Negative probe: an exchange requesting a non-consented entry
	// (timestamp:write) fails with invalid_authorization_details — the
	// RFC 9396 section 6 subset rule; printed, not fatal.
	probeAssertion, err := oidcClient.Assertion()
	if err != nil {
		return fmt.Errorf("unable to mint client assertion: %w", err)
	}
	probeProof, err := prover.Prove(http.MethodPost, md.TokenEndpoint)
	if err != nil {
		return fmt.Errorf("unable to mint DPoP proof: %w", err)
	}
	if _, errProbe := probeExchange(ctx, md, probeAssertion, probeProof, subjectRes.AccessToken, actorRes.AccessToken); errProbe != nil {
		fmt.Println("← negative probe rejected (RFC 9396 §6 subset):", errProbe)
	}

	// 10. Introspect T3: the act chain (RFC 8693 §4.4), the may_act
	// re-delegator listing and the cnf.jkt key binding.
	introspectionAssertion, err := oidcClient.Assertion()
	if err != nil {
		return fmt.Errorf("unable to mint client assertion: %w", err)
	}
	it, err := oidcClient.Introspect(ctx, introspectionAssertion, exRes.AccessToken)
	if err != nil {
		return fmt.Errorf("unable to introspect delegated token: %w", err)
	}
	fmt.Printf("← T3 introspection: client_id=%s status=%s\n", it.Metadata.GetClientId(), it.Status)
	for i, a := range it.Actor {
		fmt.Printf("←   act[%d] = %s\n", i, a.Subject)
	}

	// No error
	return nil
}

// -----------------------------------------------------------------------------
// HTTP legs

// pushAuthorizationRequest POSTs the signed request object to the PAR
// endpoint (RFC 9126 §2.1): every parameter — the request object included —
// rides the application/x-www-form-urlencoded body, keeping the signed
// object (state, nonce, code_challenge, dpop_jkt) out of URLs, access logs
// and browser history (RFC 9700 §2 exposure class).
func pushAuthorizationRequest(ctx context.Context, issuer, assertion, proof, requestObject string) (string, error) {
	params := url.Values{}
	params.Add("client_assertion_type", oidc.AssertionTypeJWTBearer)
	params.Add("client_assertion", assertion)
	params.Add("request", requestObject)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/par", strings.NewReader(params.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)

	resp, err := flowlogClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("unable to reach the PAR endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var res struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  uint64 `json:"expires_in"`
		Error      string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("unable to decode PAR response: %w", err)
	}
	if res.Error != "" || res.RequestURI == "" {
		return "", fmt.Errorf("PAR rejected the request: %s", res.Error)
	}
	return res.RequestURI, nil
}

// authorize performs the user's authentication leg (RFC 6749 section
// 4.1.1): GET /authorize consuming the PAR request_uri behind the demo
// Basic login standing in for the resource owner, and captures the 302
// JARM response from the Location header.
func authorize(ctx context.Context, issuer, clientID, requestURI string) (string, error) {
	authorizeURL := issuer + "/authorize?" + url.Values{
		"client_id":   {clientID},
		"request_uri": {requestURI},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authorizeURL, http.NoBody)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth("hello", "world")

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("unable to reach the authorization endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return "", fmt.Errorf("authorization endpoint answered HTTP %d: %s", resp.StatusCode, string(body))
	}

	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", fmt.Errorf("unable to parse the redirect location: %w", err)
	}
	response := location.Query().Get("response")
	if response == "" {
		return "", fmt.Errorf("redirect carries no JARM response parameter")
	}
	return response, nil
}

// tokenResponse is the successful token-endpoint JSON body (draft
// v2.1 section 3.2.2.1), including the RFC 9396 section 7
// authorization_details echo of the exchange.
type tokenResponse struct {
	AccessToken          string                     `json:"access_token"`
	TokenType            string                     `json:"token_type"`
	ExpiresIn            uint64                     `json:"expires_in"`
	Scope                string                     `json:"scope,omitempty"`
	AuthorizationDetails []*jsonAuthorizationDetail `json:"authorization_details,omitempty"`
	// D-12.1: the opt-in SD-JWT id_token of the code flow (digests
	// only) and its Disclosures (the user claim values).
	IDToken            string   `json:"id_token,omitempty"`
	IDTokenDisclosures []string `json:"id_token_disclosures,omitempty"`
	Error              string   `json:"error,omitempty"`
	ErrorDescription   string   `json:"error_description,omitempty"`
}

// jsonAuthorizationDetail mirrors the RFC 9396 section 5 detail shape for
// printing the echoed entries.
type jsonAuthorizationDetail struct {
	Type      string   `json:"type"`
	Locations []string `json:"locations,omitempty"`
	Actions   []string `json:"actions,omitempty"`
}

func (d *jsonAuthorizationDetail) String() string {
	raw, err := json.Marshal(d)
	if err != nil {
		return d.Type
	}
	return string(raw)
}

// postToken drives the token endpoint with the client assertion, the DPoP
// proof and the given grant parameters.
func postToken(ctx context.Context, endpoint string, params url.Values, proof string) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}

	resp, err := flowlogClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to reach the token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var res tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("unable to decode token response: %w", err)
	}
	if res.Error != "" || res.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint error: %s (%s)", res.Error, res.ErrorDescription)
	}
	return &res, nil
}

// redeemCode exchanges the authorization code with PKCE and the DPoP
// proof of the key bound through dpop_jkt (RFC 9449 section 10).
func redeemCode(ctx context.Context, md *discoveryv1.ServerMetadata, assertion, proof, code, verifier string) (*tokenResponse, error) {
	params := url.Values{}
	params.Add("grant_type", oidc.GrantTypeAuthorizationCode)
	params.Add("code", code)
	params.Add("redirect_uri", redirectURI)
	params.Add("code_verifier", verifier)
	params.Add("client_assertion_type", oidc.AssertionTypeJWTBearer)
	params.Add("client_assertion", assertion)
	return postToken(ctx, md.TokenEndpoint, params, proof)
}

// clientCredentials mints the agent's own token (RFC 8693 section 4.4
// actor: the client is the resource owner of its client_credentials
// token). The DPoP proof is mandatory: the AS resolves the agent's CIMD
// document through the metadata policy (dpop_bound_access_tokens
// defaulted per OpenID Federation 1.0 section 6.1.3.1), so the minted
// token is sender-constrained to the agent key.
func clientCredentials(ctx context.Context, md *discoveryv1.ServerMetadata, assertion, proof string) (*tokenResponse, error) {
	params := url.Values{}
	params.Add("grant_type", oidc.GrantTypeClientCredentials)
	params.Add("scope", "openid")
	params.Add("resource", mcpServerURI)
	params.Add("client_assertion_type", oidc.AssertionTypeJWTBearer)
	params.Add("client_assertion", assertion)
	return postToken(ctx, md.TokenEndpoint, params, proof)
}

// tokenExchange performs the first RFC 8693 hop: the user's token as
// subject, the agent's token as actor, the MCP tool server as target,
// and both consented mcp_tools authorization details — the MCP server's
// re-delegation requests the backend entry as a subset.
func tokenExchange(ctx context.Context, md *discoveryv1.ServerMetadata, assertion, proof, subjectToken, actorToken string) (*tokenResponse, error) {
	params := url.Values{}
	params.Add("grant_type", oidc.GrantTypeTokenExchange)
	params.Add("requested_token_type", oidc.TokenExchangeAccessTokenType)
	params.Add("subject_token", subjectToken)
	params.Add("subject_token_type", oidc.TokenExchangeAccessTokenType)
	params.Add("actor_token", actorToken)
	params.Add("actor_token_type", oidc.TokenExchangeAccessTokenType)
	params.Add("resource", mcpServerURI)
	params.Add("scope", "timestamp:read")
	params.Add("authorization_details", "["+mcpToolDetail+","+backendToolDetail+"]")
	params.Add("client_assertion_type", oidc.AssertionTypeJWTBearer)
	params.Add("client_assertion", assertion)
	return postToken(ctx, md.TokenEndpoint, params, proof)
}

// probeExchange requests a non-consented mcp_tools entry
// (timestamp:write): the RFC 9396 section 6 subset rule must reject it
// with invalid_authorization_details.
func probeExchange(ctx context.Context, md *discoveryv1.ServerMetadata, assertion, proof, subjectToken, actorToken string) (*tokenResponse, error) {
	params := url.Values{}
	params.Add("grant_type", oidc.GrantTypeTokenExchange)
	params.Add("requested_token_type", oidc.TokenExchangeAccessTokenType)
	params.Add("subject_token", subjectToken)
	params.Add("subject_token_type", oidc.TokenExchangeAccessTokenType)
	params.Add("actor_token", actorToken)
	params.Add("actor_token_type", oidc.TokenExchangeAccessTokenType)
	params.Add("resource", mcpServerURI)
	params.Add("scope", "timestamp:read")
	params.Add("authorization_details", `[{"type":"mcp_tools","locations":["http://127.0.0.1:8085"],"actions":["timestamp:write"]}]`)
	params.Add("client_assertion_type", oidc.AssertionTypeJWTBearer)
	params.Add("client_assertion", assertion)
	return postToken(ctx, md.TokenEndpoint, params, proof)
}

// invokeTool calls the get_signed_timestamp tool on the MCP server with
// the delegated token (DPoP scheme: the token is key-bound, RFC 9449
// section 7); the response body is the relayed signed timestamp.
func invokeTool(ctx context.Context, accessToken, proof string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mcpServerURI+"/tools/get_signed_timestamp/invoke", http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", proof)

	resp, err := flowlogClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to reach the mcp server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mcp server rejected the token (HTTP %d): %s", resp.StatusCode, string(raw))
	}
	return raw, nil
}

// -----------------------------------------------------------------------------
// Cryptography helpers

// signedRequest builds the ML-DSA-65-signed request object (RFC 9101):
// iss = the agent client id, aud = the issuer, exp/iat/nbf/jti mandatory,
// the authorization request parameters as claims, and the DPoP key
// thumbprint as dpop_jkt (RFC 9449 section 10 binding). The two
// mcp_tools entries are consented here (RFC 9396): the tool invocation
// on the MCP server and the backend timestamp read the MCP server
// re-delegates with — each exchange hop requests a subset of this set.
func signedRequest(expectedIssuer, state, nonce, challenge, jkt string) (string, error) {
	keySet, err := jwk.Parse([]byte(fmt.Sprintf(`{"alg":"ML-DSA-65","d":%q,"kid":%q,"kty":"AKP","pub":%q}`,
		base64.RawURLEncoding.EncodeToString(mustAgentSeed()), cimddemo.AgentClientIdentifierURL, cimddemo.AgentClientPubB64)))
	if err != nil {
		return "", fmt.Errorf("unable to decode agent key: %w", err)
	}
	privateKey, ok := keySet.Key(0)
	if !ok {
		return "", fmt.Errorf("agent JWK has no key")
	}
	keyProvider := jwk.KeyProviderFunc(func(context.Context) (jwk.Key, error) {
		return privateKey, nil
	})

	now := time.Now()
	envelope := map[string]any{
		"iss": cimddemo.AgentClientIdentifierURL,
		"aud": expectedIssuer,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"jti": random.String(16),
	}

	encoder := jwsreq.AuthorizationRequestEncoderWithOptions(
		jwt.RequestSigner("ML-DSA-65", keyProvider),
		envelope,
	)
	return encoder.Encode(context.Background(), &flowv1.AuthorizationRequest{
		Scope:               "openid timestamp:read",
		ResponseType:        "code",
		ClientId:            cimddemo.AgentClientIdentifierURL,
		RedirectUri:         redirectURI,
		State:               state,
		Nonce:               nonce,
		ResponseMode:        new("query.jwt"), // JARM (RFC 9447)
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Audience:            mcpServerURI,
		DpopJkt:             new(jkt),
		AuthorizationDetails: []*tokenv1.AuthorizationDetail{
			{Type: "mcp_tools", Locations: []string{mcpServerURI}, Actions: []string{"get_signed_timestamp"}},
			{Type: "mcp_tools", Locations: []string{backendResourceURI}, Actions: []string{"timestamp:read"}},
		},
	})
}

// mustAgentSeed decodes the fixture seed; the demo cannot run without it.
func mustAgentSeed() []byte {
	seed, err := base64.RawURLEncoding.DecodeString(cimddemo.AgentClientSeedB64)
	if err != nil {
		panic(fmt.Errorf("unable to decode agent seed: %w", err))
	}
	return seed
}

// keyThumbprint computes the RFC 7638 thumbprint of the agent key,
// base64url-encoded — the dpop_jkt value the authorization server binds
// the code to (RFC 9449 section 10).
func keyThumbprint(jwkDoc string) (string, error) {
	keySet, err := jwk.Parse([]byte(jwkDoc))
	if err != nil {
		return "", fmt.Errorf("unable to decode agent key: %w", err)
	}
	key, ok := keySet.Key(0)
	if !ok {
		return "", fmt.Errorf("agent JWK has no key")
	}
	raw, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("unable to compute thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
