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

package token

import (
	"context"
)

// IDJAGResourceServer describes a Resource Authorization Server in another
// trust domain for which this IdP may mint ID-JAGs (draft-ietf-oauth-
// identity-assertion-authz-grant-04 sections 4.3 and 5).
type IDJAGResourceServer struct {
	// Issuer identifier of the Resource Authorization Server (RFC 8414);
	// becomes the aud claim of minted ID-JAGs.
	Issuer string
	// ClientIDMapping maps a local client identifier to the client's
	// identifier at this Resource Authorization Server (draft sections
	// 3.1 and 5). Assemblies populate it out-of-band; unmapped clients
	// cannot obtain ID-JAGs for this target.
	ClientIDMapping map[string]string
}

// IDJAGAudienceResolver resolves the audience of a Token Exchange request
// for an ID-JAG to the trusted Resource Authorization Server descriptor.
// Trust is established exclusively through this resolver (pre-configured,
// never dynamic): an unknown audience fails closed.
type IDJAGAudienceResolver interface {
	// Resolve returns the Resource Authorization Server for the requested
	// audience value, or an error when it is not trusted.
	Resolve(ctx context.Context, audience string) (*IDJAGResourceServer, error)
}

// IDJAGSubjectResolution carries the subject context transcribed into an
// ID-JAG (draft section 4.3.3: claims assembly from the subject token).
type IDJAGSubjectResolution struct {
	// Subject identifier for the End-User in the target Resource
	// Authorization Server's namespace (e.g. pairwise; draft section 5).
	Subject string
	// AuthTime when the End-User authentication occurred, when known.
	AuthTime uint64
	// ACR satisfied when authenticating the End-User, when known.
	ACR string
	// AMR methods used when authenticating the End-User, when known.
	AMR []string
}

// IDJAGSubjectResolver resolves the subject of a validated subject token
// to the claim set minted into the ID-JAG for the target Resource
// Authorization Server. Assemblies implement the pairwise mapping and any
// JIT-provisioning policy; the service never invents identifiers.
type IDJAGSubjectResolver interface {
	// Resolve returns the subject resolution for the given subject token
	// claims and target Resource Authorization Server.
	Resolve(ctx context.Context, subjectTokenClaims *SubjectTokenClaims, target *IDJAGResourceServer) (*IDJAGSubjectResolution, error)
}

// SubjectTokenClaims carries the validated claims of the subject token
// presented in a Token Exchange request for an ID-JAG.
type SubjectTokenClaims struct {
	// Subject identifier within this IdP's namespace.
	Subject string
	// ClientID of the client the subject token was issued to (audience
	// binding; draft section 4.3.3).
	ClientID string
	// AuthTime / ACR / AMR carried by the subject token, when present.
	AuthTime uint64
	ACR      string
	AMR      []string
	// Scope of the authorization context the subject token represents.
	Scope string
	// AuthorizationDetails of the authorization context, when present.
	AuthorizationDetails []byte
}

// Assembly contracts are wired through WithIDJAGIssuance constructor
// options.
