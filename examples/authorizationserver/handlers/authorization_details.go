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

package handlers

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

// authorizationDetailKnownFields are the RFC 9396 section 2.2 common fields
// with a typed representation on AuthorizationDetail; every other field of
// a details object is type-specific and lands in extensions.
var authorizationDetailKnownFields = map[string]struct{}{
	"type":       {},
	"locations":  {},
	"actions":    {},
	"datatypes":  {},
	"identifier": {},
	"privileges": {},
}

// parseAuthorizationDetails decodes the authorization_details request
// parameter (RFC 9396 section 6): a JSON array of objects, each carrying a
// REQUIRED type field plus type-specific fields. The generated
// UnmarshalJSON discards unknown fields, so type-specific properties are
// split out here and preserved in the extensions map — otherwise a
// type-specific privilege (e.g. instructedAmount) would be silently
// stripped before the AS comparison.
func parseAuthorizationDetails(raw string) ([]*tokenv1.AuthorizationDetail, error) {
	var objects []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &objects); err != nil {
		return nil, fmt.Errorf("authorization_details must be a valid JSON array of objects: %w", err)
	}

	details := make([]*tokenv1.AuthorizationDetail, 0, len(objects))
	for i, obj := range objects {
		if obj == nil {
			return nil, fmt.Errorf("authorization_details[%d] must not be null", i)
		}

		known := make(map[string]json.RawMessage, len(obj))
		extensions := make(map[string]*structpb.Value, len(obj))
		for k, v := range obj {
			if _, isCommon := authorizationDetailKnownFields[k]; isCommon {
				known[k] = v
				continue
			}
			var val structpb.Value
			if err := json.Unmarshal(v, &val); err != nil {
				return nil, fmt.Errorf("authorization_details[%d].%s must be a valid JSON value: %w", i, k, err)
			}
			extensions[k] = &val
		}

		// Re-encode the common core and decode it through protojson so
		// protovalidate-annotated syntax is enforced consistently.
		knownJSON, err := json.Marshal(known)
		if err != nil {
			return nil, fmt.Errorf("unable to encode authorization_details[%d]: %w", i, err)
		}
		var d tokenv1.AuthorizationDetail
		if err := (protojson.UnmarshalOptions{}).Unmarshal(knownJSON, &d); err != nil {
			return nil, fmt.Errorf("authorization_details[%d] is malformed: %w", i, err)
		}
		if d.Type == "" {
			return nil, fmt.Errorf("authorization_details[%d] is missing the required 'type' field", i)
		}
		if len(extensions) > 0 {
			d.Extensions = extensions
		}

		details = append(details, &d)
	}

	return details, nil
}
