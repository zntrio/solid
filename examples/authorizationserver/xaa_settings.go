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
	"encoding/json"
	"fmt"
	"log"
	"os"

	"zntr.io/solid/sdk/idjag"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/pairwise"
	"zntr.io/solid/sdk/token/jwt"
	"zntr.io/solid/server/services/token"
)

// xaaConfigEnvVar is the environment variable holding the Cross-App Access
// (ID-JAG) trust configuration as a JSON document.
const xaaConfigEnvVar = "SOLID_EXAMPLE_XAA_CONFIG"

// xaaSaltEnvVar is the environment variable holding the pairwise salt for
// ID-JAG subject identifiers.
const xaaSaltEnvVar = "SOLID_EXAMPLE_XAA_SALT"

// XAAConfig models the static trust configuration of the example assembly
// for the Identity Assertion JWT Authorization Grant profile
// (draft-ietf-oauth-identity-assertion-authz-grant-04).
type XAAConfig struct {
	// TrustedIssuers maps federated IdP issuer identifiers to their JWKS
	// (Resource AS role: ID-JAGs from these issuers may be redeemed).
	TrustedIssuers map[string]json.RawMessage `json:"trusted_issuers"`

	// Audiences maps audience values accepted in Token Exchange requests
	// to Resource Authorization Server descriptors (IdP role).
	Audiences map[string]XAAAudience `json:"audiences"`
}

// XAAAudience is one trusted Resource Authorization Server.
type XAAAudience struct {
	// Issuer identifier of the Resource Authorization Server.
	Issuer string `json:"issuer"`
	// ClientIDMapping maps local client identifiers to the client's
	// identifier at the Resource Authorization Server.
	ClientIDMapping map[string]string `json:"client_id_mapping"`
}

// xaaIssuerResolver adapts TrustedIssuers to the idjag.IssuerResolver
// contract (Resource AS role).
type xaaIssuerResolver struct {
	issuers map[string]jwk.Set
}

func (r *xaaIssuerResolver) Resolve(_ context.Context, issuer string) (jwk.Set, error) {
	set, ok := r.issuers[issuer]
	if !ok {
		return nil, fmt.Errorf("issuer %q is not trusted", issuer)
	}
	return set, nil
}

// xaaAudienceResolver adapts Audiences to the token service audience
// resolver contract (IdP role).
type xaaAudienceResolver struct {
	audiences map[string]*token.IDJAGResourceServer
}

func (r *xaaAudienceResolver) Resolve(_ context.Context, audience string) (*token.IDJAGResourceServer, error) {
	target, ok := r.audiences[audience]
	if !ok {
		return nil, fmt.Errorf("audience %q is not trusted", audience)
	}
	return target, nil
}

// xaaSubjectResolver resolves subjects as salted pairwise identifiers per
// target audience (draft section 5: consistent subject identifiers across
// SSO and API access).
type xaaSubjectResolver struct {
	encoder pairwise.Encoder
}

func (r *xaaSubjectResolver) Resolve(_ context.Context, claims *token.SubjectTokenClaims, target *token.IDJAGResourceServer) (*token.IDJAGSubjectResolution, error) {
	// Sector identifier: the target Resource Authorization Server issuer.
	sub, err := r.encoder.Encode(target.Issuer, claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("unable to compute pairwise subject: %w", err)
	}
	return &token.IDJAGSubjectResolution{
		Subject:  sub,
		AuthTime: claims.AuthTime,
		ACR:      claims.ACR,
	}, nil
}

// loadXAAConfig reads the XAA trust configuration. A missing configuration
// disables both ID-JAG roles (the token service fails closed on them).
func loadXAAConfig() (*XAAConfig, error) {
	raw := os.Getenv(xaaConfigEnvVar)
	if raw == "" {
		return nil, nil //nolint:nilnil // explicit absence
	}
	var cfg XAAConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("unable to parse %s: %w", xaaConfigEnvVar, err)
	}
	return &cfg, nil
}

// xaaOptions assembles the token service options for the configured XAA
// roles. A nil config disables both roles.
func xaaOptions(cfg *XAAConfig, issuer string, signingKey jwk.KeyProviderFunc, algorithms []string) ([]token.Option, error) {
	if cfg == nil {
		log.Printf("%s not set: ID-JAG issuance and redemption are disabled", xaaConfigEnvVar)
		return nil, nil //nolint:nilnil // explicit absence
	}

	var opts []token.Option

	// Resource AS role: redeem ID-JAGs from trusted federated issuers.
	if len(cfg.TrustedIssuers) > 0 {
		issuers := make(map[string]jwk.Set, len(cfg.TrustedIssuers))
		for issuerID, rawJWKS := range cfg.TrustedIssuers {
			set, err := jwk.Parse(rawJWKS)
			if err != nil {
				return nil, fmt.Errorf("unable to parse JWKS for issuer %q: %w", issuerID, err)
			}
			issuers[issuerID] = set
		}
		opts = append(opts, token.WithIDJAGVerifier(
			idjag.DefaultVerifier(issuer, &xaaIssuerResolver{issuers: issuers}, jwt.DefaultVerifier(nil, algorithms)),
		))
	}

	// IdP role: issue ID-JAGs for trusted audiences.
	if len(cfg.Audiences) > 0 {
		audiences := make(map[string]*token.IDJAGResourceServer, len(cfg.Audiences))
		for audience, target := range cfg.Audiences {
			audiences[audience] = &token.IDJAGResourceServer{
				Issuer:          target.Issuer,
				ClientIDMapping: target.ClientIDMapping,
			}
		}
		opts = append(opts, token.WithIDJAGIssuance(
			idjag.DefaultSigner(jwt.IDJAG(defaultSigningAlgorithm, signingKey)),
			&xaaAudienceResolver{audiences: audiences},
			&xaaSubjectResolver{encoder: pairwise.Hash(xaaSubjectSalt())},
		))
	}

	return opts, nil
}

// xaaSubjectSalt returns the pairwise salt for ID-JAG subjects. Production
// assemblies should provision a dedicated secret; the example default is
// fixed only for offline demos.
func xaaSubjectSalt() []byte {
	if v := os.Getenv(xaaSaltEnvVar); v != "" {
		return []byte(v)
	}
	return []byte("solid-example-xaa-default-salt")
}

// mustXAAOptions loads the XAA configuration and assembles the token
// service options, exiting loudly on malformed configuration. The example
// server signs with ML-DSA-65 (see settings.go); the ID-JAG signer uses
// the same key material.
func mustXAAOptions(issuer string) []token.Option {
	cfg, err := loadXAAConfig()
	if err != nil {
		log.Fatalf("unable to load XAA configuration: %v", err)
	}
	opts, err := xaaOptions(cfg, issuer, keyProvider(), []string{jwk.MLDSA65})
	if err != nil {
		log.Fatalf("unable to assemble XAA options: %v", err)
	}
	return opts
}
