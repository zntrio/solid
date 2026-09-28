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

package idjag

import (
	"context"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/jwk"
)

// -----------------------------------------------------------------------------
//
//go:generate mockgen -destination mock/signer.gen.go -package mock zntr.io/solid/sdk/idjag Signer

// Signer serializes and signs an ID-JAG from its claim set.
//
// The serialized token carries typ "oauth-id-jag" qualified with the
// serializer's media-type suffix (e.g. "oauth-id-jag+jwt" for a JWT
// serializer): the serialization format is an assembly decision, not a
// property of the mechanism.
type Signer interface {
	// Serialize signs the ID-JAG claim set and returns the serialized
	// token.
	Serialize(ctx context.Context, grant *tokenv1.IdentityAssertionJWTAuthorizationGrant) (string, error)
}

// -----------------------------------------------------------------------------
//
//go:generate mockgen -destination mock/verifier.gen.go -package mock zntr.io/solid/sdk/idjag Verifier

// Verifier validates a raw ID-JAG and returns its claim set.
//
// Verification enforces, in order (draft section 4.4.1):
//   - typ header equals the expected ID-JAG type for the verifier's
//     serialization format;
//   - signature against the issuer's JWKS (algorithm allowlist);
//   - iss is trusted AND different from the local issuer identifier
//     (draft section 9.3: an AS must not honor its own ID-JAGs);
//   - aud equals the local issuer identifier, as a string or a
//     single-element array;
//   - exp/iat validity, and nbf when present;
//   - presence of jti, sub, client_id.
type Verifier interface {
	// Verify checks the raw ID-JAG against the profile rules and decodes
	// its claims. It returns the claim set on success.
	Verify(ctx context.Context, raw string) (*tokenv1.IdentityAssertionJWTAuthorizationGrant, error)
}

// -----------------------------------------------------------------------------
//
//go:generate mockgen -destination mock/issuerresolver.gen.go -package mock zntr.io/solid/sdk/idjag IssuerResolver

// IssuerResolver maps an ID-JAG issuer identifier to the JWKS used to
// verify its signatures. Trust is established exclusively through this
// resolver (pre-configured, never dynamic): an unknown issuer fails
// verification.
type IssuerResolver interface {
	// Resolve returns the key set for the given issuer identifier, or an
	// error when the issuer is not trusted.
	Resolve(ctx context.Context, issuer string) (jwk.Set, error)
}
