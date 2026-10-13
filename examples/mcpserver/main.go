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

// mcpserver demonstrates an MCP-style tool server standing between an AI
// agent and a backend resource server, on behalf of a user (RFC 8693
// delegated re-delegation):
//
//  1. the MCP server is a Client ID Metadata Document client
//     (draft-ietf-oauth-client-id-metadata-document) identified by
//     https://mcp.example.org/server;
//  2. the agent invokes the get_signed_timestamp tool with a
//     DPoP-proved, audience-restricted delegated token (T3: sub=user,
//     aud=this server, act=[agent], may_act=[this server]);
//  3. the boundary check introspects T3 (RFC 7662) and verifies the
//     act chain, the cnf.jkt proof binding and the carried mcp_tools
//     authorization detail (RFC 9396) — the tool grant is evaluated
//     here, the AS transports it;
//  4. the server re-delegates (second RFC 8693 exchange, authorized by
//     may_act): its own key becomes the new cnf (proof-of-possession
//     re-binding), the act chain extends to [mcp, agent], and the
//     backend mcp_tools detail rides the exchanged token (T5);
//  5. the backend resource server (examples/resourceserver) accepts
//     T5 and returns the signed timestamp, relayed as the tool result.
//
// Prerequisites: the example authorization server and resource server
// are running (go run ./examples/authorizationserver, go run
// ./examples/resourceserver).
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/client"
	"zntr.io/solid/examples/authorizationserver/cimddemo"
	exampleenv "zntr.io/solid/examples/internal/exampleenv"
	"zntr.io/solid/examples/internal/flowlog"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token/jwt"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage/inmemory"
)

const (
	// mcpServerURI is this server's RFC 8707 resource indicator: the
	// audience every accepted tool-invocation token must carry.
	mcpServerURI = "http://127.0.0.1:8090"

	// backendResourceURI is the backend resource server: the second
	// token-exchange hop's audience and the location the backend
	// mcp_tools detail is scoped to.
	backendResourceURI = "http://127.0.0.1:8085"
)

// toolDetail is the backend authorization_details entry of the second
// exchange hop (RFC 9396): the mcp_tools grant for the timestamp read,
// a subset of the user's consented set carried by the subject token.
const toolDetail = `{"type":"mcp_tools","locations":["http://127.0.0.1:8085"],"actions":["timestamp:read"]}`

// flowlogClient prints the protocol flow (request and response) for every
// outbound exchange of the re-delegation.
var flowlogClient = flowlog.New()

func main() {
	ctx := context.Background()
	asIssuer := exampleenv.Or("SOLID_EXAMPLE_ISSUER", "http://127.0.0.1:8080")

	// Rebuild the MCP server JWK (AKP, ML-DSA-65) from the published
	// fixture seed (agentclient precedent): the same key drives the
	// private_key_jwt client assertions and the DPoP proofs — it is the
	// K_M whose possession authorizes the may_act re-binding.
	seed, err := base64.RawURLEncoding.DecodeString(cimddemo.McpServerClientSeedB64)
	if err != nil {
		log.Fatalf("unable to decode mcp server seed: %v", err)
	}
	jwkDoc := fmt.Sprintf(`{"alg":"ML-DSA-65","d":%q,"kid":%q,"kty":"AKP","pub":%q}`,
		base64.RawURLEncoding.EncodeToString(seed), cimddemo.McpServerClientIdentifierURL, cimddemo.McpServerClientPubB64)

	// Create the OIDC client for the CIMD identifier: discovery resolves
	// the endpoints, assertions are minted with the fixture key.
	oidcClient, err := client.HTTP(ctx, asIssuer, &client.Options{
		ClientID:   cimddemo.McpServerClientIdentifierURL,
		JWK:        []byte(jwkDoc),
		HTTPClient: flowlogClient,
	})
	if err != nil {
		log.Fatalf("unable to create oidc client: %v", err)
	}
	md := oidcClient.ServerMetadata()
	if md.TokenEndpoint == "" {
		log.Fatal("server metadata does not advertise the token endpoint")
	}

	// DPoP prover over the same ML-DSA key (RFC 9449): the tool
	// invocation is proved to the agent's boundary check, and the second
	// exchange hop re-binds the delegated token to this key.
	keySet, err := jwk.Parse([]byte(jwkDoc))
	if err != nil {
		log.Fatalf("unable to decode mcp server key: %v", err)
	}
	key, ok := keySet.Key(0)
	if !ok {
		log.Fatal("mcp server JWK has no key")
	}
	prover := dpop.DefaultProver(jwt.DPoPSigner("ML-DSA-65", func(context.Context) (jwk.Key, error) {
		return key, nil
	}))

	http.Handle("/.well-known/oauth-protected-resource", resourceMetadata())
	http.Handle("/tools/get_signed_timestamp/invoke", toolInvoker(oidcClient, md, prover))

	server := &http.Server{
		// Loopback by default: the example serves plaintext HTTP — binding
		// all interfaces would expose tokens and client assertions to the
		// network.
		Addr:              exampleenv.Or("SOLID_EXAMPLE_LISTEN_ADDR", "127.0.0.1:8090"),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("mcp server listening on %s (tool: get_signed_timestamp)", server.Addr)
	log.Fatal(server.ListenAndServe())
}

// resourceMetadata serves the RFC 9728 protected-resource metadata: the
// resource indicator and the authorization server that mints tokens for
// it, so an agent can discover the AS behind a 401 challenge.
func resourceMetadata() http.Handler {
	md := &discoveryv1.ProtectedResourceMetadata{
		Resource:              mcpServerURI,
		AuthorizationServers:  []string{exampleenv.Or("SOLID_EXAMPLE_ISSUER", "http://127.0.0.1:8080")},
		ScopesSupported:       []string{"openid", "timestamp:read"},
		ResourceDocumentation: new("https://mcp.example.org/server/docs"),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(md); err != nil {
			http.Error(w, "Unable to serialize response", http.StatusInternalServerError)
		}
	})
}

// challengeInvalidToken writes the RFC 6750/9728 challenge pointing the
// caller at this resource and its metadata.
func challengeInvalidToken(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token", error_description="The access token provided is expired, revoked, malformed, or invalid for other reasons", resource="`+mcpServerURI+`", resource_metadata="`+mcpServerURI+`/.well-known/oauth-protected-resource"`)
	http.Error(w, "Unable to authenticate the tool invocation.", http.StatusUnauthorized)
}

// toolInvoker is the MCP tool boundary: DPoP proof + introspection +
// audience/act/cnf/authorization_details checks, then the re-delegation
// and the relayed backend call.
func toolInvoker(cli client.Client, md *discoveryv1.ServerMetadata, prover dpop.Prover) http.Handler {
	// The DPoP verifier rejects replayed proofs (in-memory store, demo
	// scope) and accepts the post-quantum ML-DSA keys only.
	dpopVerifier := dpop.DefaultVerifier(inmemory.DPoPProofs(), jwt.EmbeddedKeyVerifier([]string{jwk.MLDSA65}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Authorization: DPoP <T3> (RFC 9449 section 7).
		parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "dpop") {
			challengeInvalidToken(w)
			return
		}

		// Verify the DPoP proof: signature over this request with the
		// ath binding the token value.
		proofJkt, err := dpopVerifier.Verify(ctx, r.Method, dpop.CleanURL(r), r.Header.Get("DPoP"), dpop.WithTokenValue(parts[1]))
		if err != nil {
			log.Printf("dpop verification failed: %v", err)
			challengeInvalidToken(w)
			return
		}

		// Introspect the delegated token (RFC 7662): HPKE phantom
		// tokens are validated at the AS only, by design.
		assertion, err := cli.Assertion()
		if err != nil {
			log.Printf("unable to mint client assertion: %v", err)
			http.Error(w, "Internal error.", http.StatusInternalServerError)
			return
		}
		t, err := cli.Introspect(ctx, assertion, parts[1])
		if err != nil {
			log.Printf("introspection failed: %v", err)
			challengeInvalidToken(w)
			return
		}

		// Boundary checks on the delegated token:
		switch {
		case t.Status != tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE:
			challengeInvalidToken(w)
			return
		// RFC 8707: the token must be audience-restricted to this
		// server — a token minted for another resource is not a
		// credential here.
		case t.Metadata.GetAudience() != mcpServerURI:
			challengeInvalidToken(w)
			return
		// RFC 9449: the proof key must match the token's cnf.jkt
		// (possession of the agent's key K_A).
		case t.Confirmation == nil || !types.SecureCompareString(proofJkt, t.Confirmation.Jkt):
			challengeInvalidToken(w)
			return
		// RFC 8693 section 4.4: the delegation is recorded in the act
		// chain; the immediate actor must be the agent client.
		case !actorIsAgent(t.Actor):
			challengeInvalidToken(w)
			return
		// RFC 9396: the mcp_tools grant for this resource with the
		// invoked tool as action — the authorization decision of the
		// tool server.
		case !hasToolGrant(t.Metadata.GetAuthorizationDetails()):
			w.Header().Set("WWW-Authenticate", `DPoP error="insufficient_scope", error_description="The token does not carry the mcp_tools grant for this tool", resource="`+mcpServerURI+`", resource_metadata="`+mcpServerURI+`/.well-known/oauth-protected-resource"`)
			http.Error(w, "Operation not allowed for this identity.", http.StatusForbidden)
			return
		}

		// Re-delegation (second RFC 8693 hop, may_act-authorized):
		// mint the actor token, exchange T3 for the backend audience,
		// prove every leg with the MCP server key.
		backendBody, err := redelegate(ctx, cli, md, prover, parts[1])
		if err != nil {
			log.Printf("re-delegation failed: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "tool_execution_failed"})
			return
		}

		// Relay the backend signed timestamp as the tool result.
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(backendBody)
	})
}

// actorIsAgent reports whether the immediate actor of the delegation is
// the demo agent client.
func actorIsAgent(actors []*tokenv1.Actor) bool {
	if len(actors) == 0 {
		return false
	}
	return actors[0].Subject == cimddemo.AgentClientIdentifierURL
}

// hasToolGrant reports whether the token carries the mcp_tools
// authorization detail for this server with the invoked tool as action.
func hasToolGrant(details []*tokenv1.AuthorizationDetail) bool {
	for _, d := range details {
		if d == nil || d.Type != "mcp_tools" {
			continue
		}
		if types.StringArray(d.Locations).Contains(mcpServerURI) &&
			types.StringArray(d.Actions).Contains("get_signed_timestamp") {
			return true
		}
	}
	return false
}

// redelegate performs the second RFC 8693 exchange hop: the MCP server's
// client_credentials token as actor, the delegated token as subject, the
// backend resource as target — the may_act listing authorizes the cnf
// re-binding to the MCP server's key — then calls the backend with the
// exchanged token (T5) and returns the signed timestamp body.
func redelegate(ctx context.Context, cli client.Client, md *discoveryv1.ServerMetadata, prover dpop.Prover, subjectToken string) ([]byte, error) {
	// 1. Actor token: a fresh client assertion (jti single-use) and the
	// client_credentials grant.
	actorAssertion, err := cli.Assertion()
	if err != nil {
		return nil, fmt.Errorf("unable to mint client assertion: %w", err)
	}
	actorRes, err := clientCredentials(ctx, md, actorAssertion)
	if err != nil {
		return nil, fmt.Errorf("unable to mint actor token: %w", err)
	}
	log.Printf("← actor token (client_credentials): %s…", actorRes.AccessToken[:16])

	// 2. The exchange: DPoP proof over the token endpoint with the MCP
	// server key (K_M) — the proof's jkt becomes the new cnf.
	exchangeAssertion, err := cli.Assertion()
	if err != nil {
		return nil, fmt.Errorf("unable to mint client assertion: %w", err)
	}
	exchangeProof, err := prover.Prove(http.MethodPost, md.TokenEndpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to mint DPoP proof: %w", err)
	}
	exRes, err := tokenExchange(ctx, md, exchangeAssertion, exchangeProof, subjectToken, actorRes.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	log.Printf("← re-delegated access token (aud=%s, expires_in: %ds)", backendResourceURI, exRes.ExpiresIn)

	// 3. Call the backend resource server with the exchanged token,
	// proved with the same key the token is now bound to.
	backendProof, err := prover.Prove(http.MethodPost, backendResourceURI+"/", dpop.WithTokenValue(exRes.AccessToken))
	if err != nil {
		return nil, fmt.Errorf("unable to mint DPoP proof: %w", err)
	}
	return callBackend(ctx, exRes.AccessToken, backendProof)
}

// tokenResponse is the successful token-endpoint JSON body.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        uint64 `json:"expires_in"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// clientCredentials mints the MCP server's own token (RFC 8693 section
// 4.4 actor: the client is the resource owner of its client_credentials
// token; the minted subject equals the client id).
func clientCredentials(ctx context.Context, md *discoveryv1.ServerMetadata, assertion string) (*tokenResponse, error) {
	params := url.Values{}
	params.Add("grant_type", oidc.GrantTypeClientCredentials)
	params.Add("scope", "openid")
	params.Add("resource", backendResourceURI)
	params.Add("client_assertion_type", oidc.AssertionTypeJWTBearer)
	params.Add("client_assertion", assertion)
	return postToken(ctx, md.TokenEndpoint, params, "")
}

// tokenExchange performs the RFC 8693 second hop: the delegated token as
// subject, the MCP server's token as actor, the backend resource as
// target, and the RFC 9396 mcp_tools backend detail (a subset of the
// user's consented set).
func tokenExchange(ctx context.Context, md *discoveryv1.ServerMetadata, assertion, proof, subjectToken, actorToken string) (*tokenResponse, error) {
	params := url.Values{}
	params.Add("grant_type", oidc.GrantTypeTokenExchange)
	params.Add("requested_token_type", oidc.TokenExchangeAccessTokenType)
	params.Add("subject_token", subjectToken)
	params.Add("subject_token_type", oidc.TokenExchangeAccessTokenType)
	params.Add("actor_token", actorToken)
	params.Add("actor_token_type", oidc.TokenExchangeAccessTokenType)
	params.Add("resource", backendResourceURI)
	params.Add("scope", "timestamp:read")
	params.Add("authorization_details", "["+toolDetail+"]")
	params.Add("client_assertion_type", oidc.AssertionTypeJWTBearer)
	params.Add("client_assertion", assertion)
	return postToken(ctx, md.TokenEndpoint, params, proof)
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

// callBackend invokes the signed-timestamp resource with the
// re-delegated token (DPoP scheme: the token is key-bound to the MCP
// server key, RFC 9449 section 7).
func callBackend(ctx context.Context, accessToken, proof string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, backendResourceURI+"/", http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", proof)

	resp, err := flowlogClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to reach the resource server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("resource server rejected the token (HTTP %d): %s", resp.StatusCode, string(raw))
	}
	return raw, nil
}
