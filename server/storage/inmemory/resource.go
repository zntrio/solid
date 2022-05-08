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

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/server/storage"
)

type resourceStorage struct {
	backend map[string]*corev1.Resource
}

// Resources returns a resource reader.
func Resources() storage.Resource {
	return &resourceStorage{
		backend: map[string]*corev1.Resource{
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
		},
	}
}

// -----------------------------------------------------------------------------

func (s *resourceStorage) GetByURI(ctx context.Context, urn string) (*corev1.Resource, error) {
	// Check if resource exists
	resource, ok := s.backend[urn]
	if !ok {
		return nil, storage.ErrNotFound
	}

	// No error
	return resource, nil
}
