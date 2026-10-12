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

package inmemory

import (
	"context"

	resourcev1 "zntr.io/solid/api/oidc/resource/v1"
	"zntr.io/solid/server/storage"
)

type resourceStorage struct {
	backend map[string]*resourcev1.Resource
}

// mcpResourceURI is the RFC 8707 resource indicator of the example
// remote MCP-style resource server (examples/resourceserver).
const mcpResourceURI = "http://127.0.0.1:8085"

// Resources returns a resource reader.
func Resources() storage.Resource {
	return &resourceStorage{
		backend: map[string]*resourcev1.Resource{
			"urn:example:cooperation-context": {
				Urn:         "urn:example:cooperation-context",
				Description: "Example context",
			},
			"urn:example:backend-api": {
				Urn:         "urn:example:backend-api",
				Description: "Backend API",
				Urls: []string{
					"https://backend.example.com/api",
				},
			},
			// The example CWT resource server (integration/cwt_token_test):
			// audience of the client_credentials fixtures.
			"https://rs.example.org": {
				Urn:         "https://rs.example.org",
				Description: "Example CWT resource server",
				Urls:        []string{"https://rs.example.org"},
			},
			// The example remote MCP-style resource server
			// (examples/resourceserver): resolves the RFC 8707 resource
			// indicator of token-exchange requests targeting it.
			mcpResourceURI: {
				Urn:         mcpResourceURI,
				Description: "Example remote MCP-style resource server",
				Urls:        []string{mcpResourceURI},
			},
			// The cross-application-access Resource Authorization Server
			// (integration/idjag_adversarial_test): audience of the
			// ID-JAG fixtures redeemed through the jwt_bearer grant.
			"http://resource-as.example/": {
				Urn:         "http://resource-as.example/",
				Description: "Cross-application-access Resource AS",
			},
		},
	}
}

// ResourcesWith returns a resource reader pre-registered with the given
// additional resource indicators (deployments whose resource servers are
// identified by dynamically assigned addresses, e.g. the CoAP/ACE example).
func ResourcesWith(indicators ...string) storage.Resource {
	base := Resources().(*resourceStorage) //nolint:forcetypeassert // Resources returns *resourceStorage
	backend := make(map[string]*resourcev1.Resource, len(base.backend)+len(indicators))
	for urn, r := range base.backend {
		backend[urn] = r
	}
	for _, urn := range indicators {
		if urn == "" {
			continue
		}
		backend[urn] = &resourcev1.Resource{Urn: urn, Description: "Deployment resource server"}
	}
	return &resourceStorage{backend: backend}
}

// -----------------------------------------------------------------------------

func (s *resourceStorage) GetByURI(ctx context.Context, urn string) (*resourcev1.Resource, error) {
	// Check if resource exists
	resource, ok := s.backend[urn]
	if !ok {
		return nil, storage.ErrNotFound
	}

	// No error
	return resource, nil
}
