// Licensed to SolID under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. SolID licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

package cimd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// staticFetcher serves a fixed document body.
type staticFetcher struct{ body []byte }

func (f *staticFetcher) Fetch(_ context.Context, _ string) ([]byte, error) {
	return f.body, nil
}

const policyExampleDoc = `{
  "client_name": "Example Client",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "client_id": "https://example.com/client.json",
  "redirect_uris": ["https://example.com/redirect"]
}`

func TestPolicyResolverWorkedExample(t *testing.T) {
	// The session's worked example: redirect_uris.add augments the
	// fetched document; the policy-applied document feeds ToClient
	// (the URI gate validates the added loopback URI).
	p := mustPolicy(t, `{"redirect_uris": {"add": ["http://localhost:12345/redirect"]}}`)
	r := NewPolicyResolver(&staticFetcher{body: []byte(policyExampleDoc)}, p)

	c, err := r.Resolve(context.Background(), "https://example.com/client.json")
	require.NoError(t, err)

	assert.Equal(t, "Example Client", c.ClientName)
	assert.Equal(t, "none", c.TokenEndpointAuthMethod)
	assert.ElementsMatch(t, []string{"https://example.com/redirect", "http://localhost:12345/redirect"}, c.RedirectUris)
	assert.ElementsMatch(t, []string{"authorization_code", "refresh_token"}, c.GrantTypes)
}

func TestPolicyResolverDefaultsExistingField(t *testing.T) {
	// default fills an absent field that ToClient maps (subject_type).
	p := mustPolicy(t, `{"subject_type": {"default": "pairwise"}}`)
	r := NewPolicyResolver(&staticFetcher{body: []byte(policyExampleDoc)}, p)

	c, err := r.Resolve(context.Background(), "https://example.com/client.json")
	require.NoError(t, err)
	assert.Equal(t, "pairwise", c.SubjectType)
}

func TestPolicyResolverSmuggledSecretMethodRejected(t *testing.T) {
	// §4.1 ORDER PROOF: the policy runs BEFORE ToClient's credential
	// restrictions, so a policy cannot smuggle a shared-secret auth
	// method past the enforcement — the policy-applied document is what
	// gets validated. The fetched document itself is clean; the policy
	// is the attacker-controlled input here.
	p := mustPolicy(t, `{"token_endpoint_auth_method": {"value": "client_secret_basic"}}`)
	r := NewPolicyResolver(&staticFetcher{body: []byte(policyExampleDoc)}, p)

	_, err := r.Resolve(context.Background(), "https://example.com/client.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestPolicyResolverOneOfViolationRejectsClient(t *testing.T) {
	// The fetched document violates the policy: the whole client is
	// rejected (fail-closed — unknown client, like an unfetchable doc).
	p := mustPolicy(t, `{"token_endpoint_auth_method": {"one_of": ["private_key_jwt"]}}`)
	r := NewPolicyResolver(&staticFetcher{body: []byte(policyExampleDoc)}, p)

	_, err := r.Resolve(context.Background(), "https://example.com/client.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "one_of")
}

func TestPolicyResolverEssentialAbsentRejectsClient(t *testing.T) {
	p := mustPolicy(t, `{"jwks_uri": {"essential": true}}`)
	r := NewPolicyResolver(&staticFetcher{body: []byte(policyExampleDoc)}, p)

	_, err := r.Resolve(context.Background(), "https://example.com/client.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "essential")
}

func TestPolicyResolverClientIDRewriteRejected(t *testing.T) {
	// A policy entry on client_id could rewrite the identifier the
	// document was fetched from, breaking the draft section 4 match —
	// forbidden outright.
	p := mustPolicy(t, `{"client_id": {"value": "https://attacker.example.com/doc"}}`)
	r := NewPolicyResolver(&staticFetcher{body: []byte(policyExampleDoc)}, p)

	_, err := r.Resolve(context.Background(), "https://example.com/client.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id")
}

func TestPolicyResolverAddedRedirectURIGate(t *testing.T) {
	// Policy-added redirect URIs run the https-or-RFC 8252-loopback
	// gate: an https URI to an attacker host fails even though the
	// policy operator itself has no host restrictions — the gate is
	// about scheme and shape, not trust.
	ok := mustPolicy(t, `{"redirect_uris": {"add": ["http://localhost:9999/cb"]}}`)
	r := NewPolicyResolver(&staticFetcher{body: []byte(policyExampleDoc)}, ok)
	_, err := r.Resolve(context.Background(), "https://example.com/client.json")
	require.NoError(t, err)

	bad := mustPolicy(t, `{"redirect_uris": {"add": ["ftp://localhost:9999/cb"]}}`)
	r2 := NewPolicyResolver(&staticFetcher{body: []byte(policyExampleDoc)}, bad)
	_, err = r2.Resolve(context.Background(), "https://example.com/client.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect_uri")
}

func TestPolicyResolverNilPolicyPassThrough(t *testing.T) {
	// NewResolver (nil policy) behaves exactly as before the feature.
	r := NewResolver(&staticFetcher{body: []byte(policyExampleDoc)})
	c, err := r.Resolve(context.Background(), "https://example.com/client.json")
	require.NoError(t, err)
	assert.Equal(t, []string{"https://example.com/redirect"}, c.RedirectUris)
	assert.Empty(t, c.SubjectType)
}

func TestPolicyResolverFetchedDocumentBadURIRejected(t *testing.T) {
	// Pre-existing gap closed: even without any policy, ToClient now
	// rejects non-https non-loopback redirect URIs in fetched documents.
	badDoc := `{
	  "client_id": "https://example.com/client.json",
	  "token_endpoint_auth_method": "none",
	  "redirect_uris": ["http://evil.example.com/cb"]
	}`
	r := NewResolver(&staticFetcher{body: []byte(badDoc)})
	_, err := r.Resolve(context.Background(), "https://example.com/client.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect_uri")
}

// aiAgentDoc is the CIMD document shape of the AI-agent examples
// (examples/agentclient, examples/mcpserver — fields mirroring the
// cimddemo fixtures): neither declares dpop_bound_access_tokens, so the
// example AS policy's default is what governs their sender-binding
// posture at the token endpoint.
const aiAgentDoc = `{
  "client_id": "https://agent.example.org/ai-agent",
  "client_name": "ai-agent",
  "token_endpoint_auth_method": "private_key_jwt",
  "subject_type": "pairwise",
  "sector_identifier": "https://agent.example.org",
  "grant_types": ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "client_credentials"],
  "response_types": ["code"],
  "response_modes": ["query.jwt"],
  "redirect_uris": ["http://127.0.0.1:8100/callback"]
}`

func TestPolicyResolverAIAgentExamplesDpopBound(t *testing.T) {
	// The example authorization server's policy (wired in
	// examples/authorizationserver/main.go) defaults
	// dpop_bound_access_tokens for the AI-agent examples: the agent
	// client and the MCP server prove DPoP on every request, and the
	// policy pins that posture at the resolver instead of trusting the
	// remote documents to declare it.
	p := mustPolicy(t, `{"dpop_bound_access_tokens": {"default": true, "essential": true}, "subject_type": {"default": "pairwise"}}`)
	r := NewPolicyResolver(&staticFetcher{body: []byte(aiAgentDoc)}, p)

	c, err := r.Resolve(context.Background(), "https://agent.example.org/ai-agent")
	require.NoError(t, err)
	assert.True(t, c.DpopBoundAccessTokens, "policy default must set the sender-binding posture for AI-agent clients")
	assert.Equal(t, "pairwise", c.SubjectType)

	// essential: a document omitting the field entirely still resolves
	// (default fills it first — the spec's operator order: default After
	// add, essential Last), and one_of would reject a non-conforming
	// value. The essential+absent error path is covered by
	// TestPolicyResolverEssentialAbsentRejectsClient for fields without
	// a default.
}
