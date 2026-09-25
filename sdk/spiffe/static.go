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

package spiffe

import (
	"context"
	"fmt"

	"zntr.io/solid/sdk/jwk"
)

// -----------------------------------------------------------------------------

type staticBundleSource struct {
	bundles map[string]jwk.Set
}

// NewStaticBundleSource builds a BundleSource over pre-configured trust
// bundles (draft section 6.2.2): the static alternative to bundle endpoints,
// for trust domains whose keys are established out of band. The input map is
// copied so later mutation by the caller has no effect.
func NewStaticBundleSource(bundles map[string]jwk.Set) BundleSource {
	copied := make(map[string]jwk.Set, len(bundles))
	for td, set := range bundles {
		copied[td] = set
	}
	return &staticBundleSource{bundles: copied}
}

// Get returns the pre-configured bundle for the trust domain. Unknown trust
// domains are an error: no key discovery from SVIDs ever happens.
func (s *staticBundleSource) Get(_ context.Context, trustDomain string) (jwk.Set, error) {
	set, ok := s.bundles[trustDomain]
	if !ok || set == nil || set.Len() == 0 {
		return nil, fmt.Errorf("spiffe: no bundle configured for trust domain %q", trustDomain)
	}
	return set, nil
}

var _ BundleSource = (*staticBundleSource)(nil)
