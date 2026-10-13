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
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"zntr.io/solid/examples/authorizationserver/cimddemo"
	"zntr.io/solid/examples/authorizationserver/spiffedemo"
	exampleenv "zntr.io/solid/examples/internal/exampleenv"
	"zntr.io/solid/sdk/authzdetails"
	"zntr.io/solid/sdk/cimd"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/generator"
	"zntr.io/solid/sdk/jarm"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/pairwise"
	"zntr.io/solid/sdk/sdtoken"
	"zntr.io/solid/sdk/sdtoken/sdjwt"
	"zntr.io/solid/sdk/spiffe"
	sdktoken "zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/hpke"
	"zntr.io/solid/sdk/token/jwt"
	tokensd "zntr.io/solid/sdk/token/sd"
	"zntr.io/solid/server/httpkit"
	"zntr.io/solid/server/profile"
	"zntr.io/solid/server/services/authorization"
	"zntr.io/solid/server/services/backchannel"
	"zntr.io/solid/server/services/device"
	"zntr.io/solid/server/services/token"
	"zntr.io/solid/server/storage/inmemory"
)

// es256Alg is the ECDSA P-256 signature algorithm accepted alongside the
// post-quantum ML-DSA-65 (elliptic curves + PQ only, repo rule).
const es256Alg = "ES256"

// clientAssertionAlgorithms is the elliptic-curve + post-quantum signing
// allowlist shared by every assertion-verification surface (client
// authentication, backchannel requests, DPoP proofs).
var clientAssertionAlgorithms = []string{es256Alg, jwk.MLDSA65}

// requestObjectAlgorithms is the request-object verifier allowlist: the
// reference posture accepts the post-quantum ML-DSA-65 only.
var requestObjectAlgorithms = []string{jwk.MLDSA65}

// authDetailsTypes are the RFC 9396 authorization details types the example
// AS registers and validates: payment initiation, and the MCP tool grant
// consumed by the agentclient / resourceserver demos.
var authDetailsTypes = []string{"payment_initiation", "mcp_tools"}

// authDetailsValidator is the details-type validator built from the
// registered types above.
var authDetailsValidator = authzdetails.NewStaticValidator(sliceToSet(authDetailsTypes))

func sliceToSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return set
}

//nolint:funlen // example assembly: linear wiring of the reference stack
func main() {
	// Generators
	authorizationCodes := generator.DefaultAuthorizationCode()
	requestURIs := generator.DefaultRequestURI()
	deviceCodes := generator.DefaultDeviceCode()
	deviceUserCodes := generator.DefaultDeviceUserCode()
	authReqIDs := generator.DefaultAuthReqID()

	// Storage key for keyed hashing of in-memory indexes. Generated at boot:
	// the example server does not persist storage across restarts.
	storageKey := make([]byte, 32)
	if _, err := rand.Read(storageKey); err != nil {
		panic(fmt.Errorf("unable to generate storage key: %w", err))
	}

	// Create storage
	resources := inmemory.Resources()
	tokens := inmemory.Tokens(storageKey)
	// Wrap in-memory client storage with CIMD resolution: pre-registered
	// clients win, URL-shaped https:// client identifiers without a stored
	// registration are resolved from their Client ID Metadata Document.
	// The AS is only authorized to pull documents for the explicitly
	// allow-listed identifiers below: CIMD resolution is a server-side
	// fetch triggered by a client-supplied identifier, so the host
	// surface is pinned by the operator, never by the caller. The demo
	// document fixture (examples/authorizationserver/cimddemo) is served
	// by an in-memory fetcher; remote documents would go through the
	// hardened httpfetch (SSRF pre-flight, https-only), itself still
	// behind the allow-list.
	cimdResolver := cimd.NewAllowlistFilter(
		cimd.NewResolver(cimddemo.StaticFetcher()),
		// Operator-pinned identifiers and hosts authorized for CIMD
		// resolution. Prefix entries (trailing slash) grant a whole
		// remote host.
		cimddemo.ClientIdentifierURL,
		cimddemo.AgentClientIdentifierURL,
		cimddemo.McpServerClientIdentifierURL,
		cimddemo.ResourceServerClientIdentifierURL,
	)
	clients := inmemory.NewClientReader(inmemory.Clients(), cimdResolver)
	proofs := inmemory.DPoPProofs()
	authRequests := inmemory.AuthorizationRequests(storageKey)
	authSessions := inmemory.AuthorizationCodeSessions(storageKey)
	deviceSessions := inmemory.DeviceCodeSessions(storageKey)
	backchannelSessions := inmemory.BackchannelAuthenticationSessions(storageKey)
	// Token generators: HPKE-encrypted JWTs
	// (draft-ietf-jose-hpke-encrypt-22 Integrated Encryption, HPKE-7) over
	// the ES256/ML-DSA-65 signed inner tokens — sign-then-encrypt.
	atSerializer := sdktoken.Encryption(
		jwt.AccessTokenSigner(defaultSigningAlgorithm, keyProvider()),
		hpke.Encrypter(defaultEncryptionAlgorithm, encryptionKeyProvider()),
	)
	rtSerializer := sdktoken.Encryption(
		jwt.RefreshTokenSigner(defaultSigningAlgorithm, keyProvider()),
		hpke.Encrypter(defaultEncryptionAlgorithm, encryptionKeyProvider()),
	)
	accessTokens := sdktoken.AccessToken(atSerializer)
	refreshTokens := sdktoken.RefreshToken(rtSerializer)

	// D-12.1 opt-in: selectively disclosable id_token (SD id+jwt) — digests
	// in the token, values in the response id_token_disclosures.
	idTokenIssuer, err := sdjwt.NewAccessTokenIssuer(sdtoken.IDTokenProfile, sdjwt.Deps{
		Signer: jwt.RawTypedSigner("id+jwt", defaultSigningAlgorithm, keyProvider()),
	})
	if err != nil {
		panic(fmt.Errorf("unable to build id_token issuer: %w", err))
	}
	idTokens := tokensd.IDTokenWithSelectiveDisclosure(
		idTokenIssuer,
		nil, // no extra protected claims
		map[string]any{ // demo attributes of the single demo subject ("hello")
			"email": "hello@example.org",
			"name":  "Hello World",
		},
	)

	// Prepare services
	authz := authorization.New(clients, authRequests, authSessions, authorizationCodes, requestURIs,
		authDetailsValidator)

	// Cross-App Access (ID-JAG) roles: static trust configuration from
	// SOLID_EXAMPLE_XAA_CONFIG; absent configuration disables both roles.
	issuer := exampleenv.Or("SOLID_EXAMPLE_ISSUER", "http://127.0.0.1:8080")
	xaaOpts := mustXAAOptions(issuer)
	tokenz := token.NewWithOptions(accessTokens, refreshTokens, clients, authSessions, deviceSessions, backchannelSessions, tokens, resources, append(xaaOpts,
		// RFC 8693 may_act delegation posture for the demo topology: the
		// MCP server may re-delegate user tokens minted for it
		// (examples/mcpserver → examples/resourceserver second hop).
		token.WithDelegationPolicy(staticDelegationPolicy{
			"http://127.0.0.1:8090": {cimddemo.McpServerClientIdentifierURL},
		}),
		token.WithIDTokenGenerator(idTokens))...)
	devicez := device.New(clients, deviceSessions, deviceCodes, deviceUserCodes, inmemory.UserCodeAttempts(), authDetailsValidator)
	backchannelz := backchannel.New(clients, backchannelSessions, authReqIDs, backchannel.LoginHintResolver(), authDetailsValidator, clientAssertionAlgorithms)

	// SPIFFE trust bundles (draft-ietf-oauth-spiffe-client-auth-02 section 6):
	// the example.org trust domain keys are pre-configured statically; the
	// bundle is also served at /spiffe/bundle.json so a bundle-endpoint
	// consumer can fetch it (the demo assembly itself uses the static source,
	// httpfetch refuses loopback fetches by SSRF hardening).
	spiffeBundleSet := jwk.NewSet()
	_ = spiffeBundleSet.Set("keys", []jwk.Key{func() jwk.Key {
		k := spiffedemo.JWTSVIDPublicKey()
		_ = k.Set(jwk.KeyUsageKey, spiffe.KeyUseJWTSVID)
		return k
	}()})
	spiffeBundles := spiffe.NewStaticBundleSource(map[string]jwk.Set{
		spiffedemo.TrustDomain: spiffeBundleSet,
	})

	// Middlewares
	// The strict application-type profile constrains clients whose
	// application_type maps to a profile entry (grants, response types,
	// token-endpoint auth methods); other clients fall back to their
	// registration metadata.
	profiles := profile.Strict()
	secHeaders := httpkit.SecurityHeaders()
	basicAuth := httpkit.BasicAuthentication(func(u, p string) (string, *httpkit.AuthenticationEvent, bool) {
		// Demo credentials for the resource-owner login surface.
		if u == "hello" && p == "world" {
			// RFC 9470: the demo Basic login achieves this authentication
			// context class reference.
			return u, &httpkit.AuthenticationEvent{
				ACR:      "urn:solid:loa:1fa:any",
				AuthTime: uint64(time.Now().Unix()), //nolint:gosec // unix time is non-negative
			}, true
		}
		return "", nil, false
	})
	clientAuth := httpkit.ClientAuthentication(clients, issuer, clientAssertionAlgorithms, spiffeBundles, proofs, profiles)

	// Request encoders
	keys := keyProvider()
	keySet := keySetProvider()
	dpopVerifier := dpop.DefaultVerifier(proofs, jwt.DefaultVerifier(keySet, clientAssertionAlgorithms))
	jarmEncoder := jarm.Encoder(jwt.JARMSigner(jwk.MLDSA65, keys))
	pairwiseEncoder := pairwise.Hash(examplePairwiseSalt())

	// Create router
	md := metadataDocument(issuer)
	http.Handle("/.well-known/oauth-authorization-server", httpkit.Metadata(md, jwt.ServerMetadata(jwk.MLDSA65, keys)))
	http.Handle("/.well-known/openid-configuration", httpkit.Metadata(md, jwt.ServerMetadata(jwk.MLDSA65, keys)))
	http.Handle("/keys", httpkit.JWKS(keySet))
	http.Handle("/spiffe/bundle.json", httpkit.SpiffeBundle(spiffeBundleSet))
	realm := httpkit.WithErrorIssuer(issuer)
	http.Handle("/par", httpkit.Adapt(httpkit.PushedAuthorizationRequest(issuer, authz, dpopVerifier, requestObjectAlgorithms, profiles), clientAuth, realm))
	http.Handle("/authorize", httpkit.Adapt(httpkit.Authorization(issuer, authz, clients, jarmEncoder, pairwiseEncoder, requestObjectAlgorithms, profiles), secHeaders, basicAuth, realm))
	http.Handle("/token", httpkit.Adapt(httpkit.Token(issuer, tokenz, dpopVerifier, profiles), clientAuth, realm))
	http.Handle("/token/introspect", httpkit.Adapt(httpkit.TokenIntrospection(issuer, tokenz), clientAuth, realm))
	http.Handle("/token/revoke", httpkit.Adapt(httpkit.TokenRevocation(issuer, tokenz), clientAuth, realm))
	http.Handle("/device/authorize", httpkit.Adapt(httpkit.DeviceAuthorization(issuer, devicez, fmt.Sprintf("%s/device", issuer)), clientAuth, realm))
	http.Handle("/device", httpkit.Adapt(httpkit.Device(issuer, devicez), secHeaders, basicAuth, realm))
	http.Handle("/bc-authorize", httpkit.Adapt(httpkit.BackchannelAuthorization(issuer, backchannelz), clientAuth, realm))
	http.Handle("/backchannel", httpkit.Adapt(httpkit.BackchannelValidation(issuer, backchannelz), secHeaders, basicAuth, realm))

	listenAddr := os.Getenv("SOLID_EXAMPLE_LISTEN_ADDR")
	if listenAddr == "" {
		// Loopback by default: the example serves plaintext HTTP — binding
		// all interfaces would expose tokens, client assertions and Basic
		// credentials to the network.
		listenAddr = "127.0.0.1:8080"
	}
	server := &http.Server{
		Addr:              listenAddr,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

// examplePairwiseSalt provisions the pairwise subject salt: an explicit
// secret via SOLID_EXAMPLE_PAIRWISE_SALT, or an ephemeral random salt with
// a loud warning. A committed default salt would be derivable by anyone
// with repo access, defeating the pairwise unlinkability posture; an
// ephemeral salt invalidates pairwise subjects across restarts, which is
// the acceptable demo trade-off (mirroring the ephemeral signing key).
func examplePairwiseSalt() []byte {
	if v := os.Getenv("SOLID_EXAMPLE_PAIRWISE_SALT"); v != "" {
		return []byte(v)
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		panic(fmt.Errorf("unable to generate pairwise salt: %w", err))
	}
	log.Println("WARNING: SOLID_EXAMPLE_PAIRWISE_SALT is not set; using an ephemeral salt. Pairwise subject identifiers will not survive a restart; set the variable for anything beyond local testing.")
	return salt
}

// staticDelegationPolicy is the fixed demo delegation policy (RFC 8693
// may_act issuance): a resource URI → re-delegator client IDs map. It
// answers the token-exchange grant when minting tokens for a target
// resource, listing the clients authorized to re-delegate them.
type staticDelegationPolicy map[string][]string

// MayRedelegate implements token.DelegationPolicy.
func (p staticDelegationPolicy) MayRedelegate(_ context.Context, resourceURI string) ([]string, error) {
	return p[resourceURI], nil
}
