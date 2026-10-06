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

// HasJKT reports whether the claims carry a non-empty cnf.jkt
// confirmation member (draft-forten section 5.3 binding form).
func HasJKT(claims map[string]any) bool {
	cnf, has := claims["cnf"]
	if !has {
		return false
	}
	cnfMap, ok := cnf.(map[string]any)
	if !ok {
		return false
	}
	jkt, ok := cnfMap["jkt"].(string)
	return ok && jkt != ""
}

// CloneClaims deep-copies a claims map ahead of issuance: the
// serialization engines replace Disclosable / DisclosableElement
// markers with digests IN the tree (deleting map entries, rewriting
// array elements), so a shallow copy leaves the caller's nested
// arrays corrupted after Issue. Markers themselves are copied
// value-intact (their Value is referenced, never mutated — only
// replaced), so marker values may stay shared.
func CloneClaims(claims map[string]any) map[string]any {
	if claims == nil {
		return nil
	}
	out := make(map[string]any, len(claims))
	for k, v := range claims {
		out[k] = cloneValue(v)
	}
	return out
}

// cloneValue copies the containers the issuance walk can mutate:
// maps and slices. Leaf values are shared (never rewritten in place).
func cloneValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, vv := range typed {
			out[k] = cloneValue(vv)
		}
		return out
	case map[any]any:
		out := make(map[any]any, len(typed))
		for k, vv := range typed {
			out[k] = cloneValue(vv)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, vv := range typed {
			out[i] = cloneValue(vv)
		}
		return out
	default:
		return v
	}
}
