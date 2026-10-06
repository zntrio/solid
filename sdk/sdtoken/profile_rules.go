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

package sdtoken

import "fmt"

// ValidateDisclosableClaims enforces the draft-forten profile rules on a
// claim map before issuance, walking marker positions at the top level
// only:
//
//   - a Disclosable / DisclosableElement marker whose claim name is in
//     profile.ProtectedClaims is rejected (ErrProtectedClaim): the claim
//     a relying party validates to trust the token MUST stay in the
//     signed payload (draft-forten section 3).
//   - a marker nested deeper than the top level is rejected
//     (ErrNestedDisclosable): draft-forten section 3 forbids nested _sd
//     and recursive disclosures.
//
// Element markers sitting directly inside a DISCLOSABLE array-valued
// top-level claim are allowed; markers anywhere deeper, inside marker
// values, or inside protected claims (including their arrays) are
// rejected.
//
//nolint:gocyclo // linear draft-forten section 3 rule dispatch, one guard per claim shape
func ValidateDisclosableClaims(profile Profile, claims map[string]any) error {
	if claims == nil {
		return fmt.Errorf("%w: claims map is nil", ErrInvalidToken)
	}

	for name, value := range claims {
		switch typed := value.(type) {
		case Disclosable:
			if _, protected := profile.ProtectedClaims[name]; protected {
				return fmt.Errorf("%w: %s is protected by the %s profile", ErrProtectedClaim, name, profile.Name)
			}
			// No recursive disclosures (draft-forten section 3: every
			// disclosure names a top-level claim and stands on its
			// own): a marker inside a marker's value is rejected.
			if err := rejectNestedMarkers(name, typed.Value); err != nil {
				return err
			}
		case DisclosableElement:
			if _, protected := profile.ProtectedClaims[name]; protected {
				return fmt.Errorf("%w: %s is protected by the %s profile", ErrProtectedClaim, name, profile.Name)
			}
			if err := rejectNestedMarkers(name, typed.Value); err != nil {
				return err
			}
		case []any:
			if _, protected := profile.ProtectedClaims[name]; protected {
				// Element markers are only legal under DISCLOSABLE
				// top-level claims: a marker inside a protected
				// claim's array would redact a permission value
				// (scope, authorization_details) — reject it.
				for _, element := range typed {
					if _, isMarker := element.(DisclosableElement); isMarker {
						return fmt.Errorf("%w: %s is protected by the %s profile", ErrProtectedClaim, name, profile.Name)
					}
				}
				if err := rejectNestedMarkers(name, typed); err != nil {
					return err
				}
			} else {
				// Element markers directly under the top-level array
				// are allowed; anything deeper is not.
				for i, element := range typed {
					switch element.(type) {
					case Disclosable, DisclosableElement:
					default:
						if err := rejectNestedMarkers(fmt.Sprintf("%s[%d]", name, i), element); err != nil {
							return err
						}
					}
				}
			}
		default:
			if err := rejectNestedMarkers(name, value); err != nil {
				return err
			}
		}
	}
	return nil
}

// rejectNestedMarkers walks a claim subtree, rejecting any Disclosable /
// DisclosableElement found anywhere within it (draft-forten section 3:
// no nested or recursive disclosures).
func rejectNestedMarkers(path string, node any) error {
	switch typed := node.(type) {
	case Disclosable, DisclosableElement:
		return fmt.Errorf("%w: marker for %q sits below the top claim level", ErrNestedDisclosable, path)
	case map[string]any:
		for k, v := range typed {
			if err := rejectNestedMarkers(path+"."+k, v); err != nil {
				return err
			}
		}
	case map[any]any:
		for k, v := range typed {
			if err := rejectNestedMarkers(fmt.Sprintf("%s.%v", path, k), v); err != nil {
				return err
			}
		}
	case []any:
		for i, v := range typed {
			if err := rejectNestedMarkers(fmt.Sprintf("%s[%d]", path, i), v); err != nil {
				return err
			}
		}
	}
	return nil
}
