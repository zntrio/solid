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

package httpkit

import (
	"net/http"

	"google.golang.org/protobuf/proto"

	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
	"zntr.io/solid/sdk/token"
)

// Metadata handles RFC 8414 authorization server metadata requests: it
// serves the supplied metadata document, augmented with a signed_metadata
// value produced by the signer.
func Metadata(md *discoveryv1.ServerMetadata, signer token.Signer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never mutate the assembler-supplied document: clone it before
		// attaching the per-request signed_metadata value.
		mdCopy := proto.Clone(md).(*discoveryv1.ServerMetadata)

		// Create signed metadata
		signedMeta, err := signer.Sign(r.Context(), mdCopy)
		if err != nil {
			http.Error(w, "unable to sign metadata", http.StatusInternalServerError)
			return
		}

		// Assign signed metadata
		mdCopy.SignedMetadata = signedMeta

		// Return JSON
		WithJSON(w, http.StatusOK, mdCopy)
	})
}
