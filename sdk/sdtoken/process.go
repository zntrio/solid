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

import "reflect"

// ProcessOptions tunes the disclosure-processing fixpoint engine per
// role.
type ProcessOptions struct {
	// HolderSemantics selects holder-role completeness checks: every
	// disclosure must match exactly one redaction site (unreferenced
	// disclosures are rejected), while unmatched sites (decoy digests)
	// are tolerated since decoys are indistinguishable from redacted
	// claims at the digest level. Verifier semantics (false) skips
	// undisclosed elements instead and rejects nothing on the site side.
	HolderSemantics bool
}

// Process matches disclosures against the redaction sites of the decoded
// claim tree, inserts disclosed values, recursively processes newly
// disclosed subtrees (nested redactions inside disclosures, any order,
// fixpoint until no site remains), and removes undisclosed elements. It
// returns the processed tree (digest containers stripped) and the set of
// matched digest keys (RFC 9901 section 7.1 steps 3-5,
// draft-ietf-spice-sd-cwt-08 sections 7 and 9 step 8).
func Process(adapter FormatAdapter, root any, disclosures []DecodedDisclosure, opts ProcessOptions) (processed any, matched map[string]struct{}, err error) {
	// Step 1: digest -> disclosure table; duplicate digests are rejected
	// regardless of role (RFC 9901 section 7.1 step 3,
	// draft section 9 step 8).
	table, tableErr := buildDisclosureTable(disclosures)
	if tableErr != nil {
		return nil, nil, tableErr
	}

	matched = map[string]struct{}{}

	// Fixpoint: sites inside newly disclosed values appear only after
	// insertion, so iterate until a full pass adds nothing.
	for {
		sites, errSites := adapter.ClaimTreeDigestSites(root)
		if errSites != nil {
			return nil, nil, errSites
		}
		if len(sites) == 0 {
			break
		}

		progressed, errApply := applyDisclosures(adapter, sites, table, matched)
		if errApply != nil {
			return nil, nil, errApply
		}
		if !progressed {
			break
		}
	}

	// After the fixpoint: verifier semantics remove every remaining
	// (undisclosed) redacted element; digest containers are stripped in
	if errRemove := removeUndisclosedElements(adapter, table, root, opts.HolderSemantics); errRemove != nil {
		return nil, nil, errRemove
	}

	if errStrip := stripDigestContainers(adapter, root); errStrip != nil {
		return nil, nil, errStrip
	}

	// Every disclosure must have been consumed: an unconsumed disclosure
	// is either unsolicited (verifier) or an incomplete transfer
	// (holder). This also catches recursive "child without parent"
	// attacks: a nested disclosure whose parent was never disclosed has
	// no matching site at any depth.
	if len(matched) != len(disclosures) {
		return nil, nil, ErrUnreferencedDisclosure
	}

	return root, matched, nil
}

// buildDisclosureTable indexes disclosures by digest key, rejecting
// duplicates (RFC 9901 section 7.1 step 3, draft section 9 step 8).
func buildDisclosureTable(disclosures []DecodedDisclosure) (map[string]DecodedDisclosure, error) {
	table := make(map[string]DecodedDisclosure, len(disclosures))
	for _, d := range disclosures {
		if _, exists := table[d.Digest]; exists {
			return nil, ErrDuplicateDigest
		}
		table[d.Digest] = d
	}
	return table, nil
}

// applyDisclosures consumes one pass of redaction sites against the
// disclosure table, inserting disclosed values and updating matched.
// It reports whether any site progressed (drives the fixpoint).
func applyDisclosures(adapter FormatAdapter, sites []RedactionSite, table map[string]DecodedDisclosure, matched map[string]struct{}) (bool, error) {
	progressed := false
	for _, site := range sites {
		disclosure, found := table[site.Digest]
		if !found {
			// Unmatched site: verifier semantics tolerate it (may be
			// a decoy or an undisclosed claim); holder semantics also
			// tolerate it (decoy digests carry no disclosure), since
			// holder completeness is enforced by the unreferenced-
			// disclosure check in Process.
			continue
		}
		if _, already := matched[site.Digest]; already {
			continue
		}

		if err := applyDisclosureAtSite(adapter, site, &disclosure); err != nil {
			return false, err
		}

		matched[site.Digest] = struct{}{}
		progressed = true
	}
	return progressed, nil
}

// applyDisclosureAtSite validates a disclosure against its site kind
// (arity, decoy form, reserved keys) and performs the insertion.
func applyDisclosureAtSite(adapter FormatAdapter, site RedactionSite, disclosure *DecodedDisclosure) error {
	switch site.Kind {
	case KindMap:
		if disclosure.IsDecoy {
			return ErrInvalidDisclosure
		}
		// Map sites require the 3-element disclosure form.
		if disclosure.ClaimKey == nil {
			return ErrInvalidDisclosure
		}
		if ReservedKey(disclosure.ClaimKey) {
			return ErrInvalidDisclosure
		}
		return adapter.InsertMapClaim(site, disclosure.ClaimKey, disclosure.Value)
	case KindElement:
		if disclosure.IsDecoy {
			return ErrInvalidDisclosure
		}
		// Element sites require the 2-element disclosure form.
		if disclosure.ClaimKey != nil {
			return ErrInvalidDisclosure
		}
		return adapter.ReplaceElement(site, disclosure.Value)
	default:
		return ErrInvalidDisclosure
	}
}

// removeUndisclosedElements deletes every remaining redacted element
// under verifier semantics (holder semantics keep them: their absence
// of a disclosure is not an error there).
func removeUndisclosedElements(adapter FormatAdapter, table map[string]DecodedDisclosure, root any, holderSemantics bool) error {
	finalSites, err := adapter.ClaimTreeDigestSites(root)
	if err != nil {
		return err
	}
	for _, site := range finalSites {
		if _, found := table[site.Digest]; !found && !holderSemantics && site.Kind == KindElement {
			if err := adapter.RemoveElement(site); err != nil {
				return err
			}
		}
	}
	return nil
}

// stripDigestContainers removes every digest-array container from the
// tree, iterating to a fixpoint: disclosed values may themselves
// contain containers, and stripping one does not invalidate other
// sites' Parent references. Parents are maps or slices: not
// comparable as map keys, so dedup runs on their Go pointer identity
// (reflect-based, nil-safe).
func stripDigestContainers(adapter FormatAdapter, root any) error {
	strippedParents := map[uintptr]struct{}{}
	for {
		sites, err := adapter.ClaimTreeDigestSites(root)
		if err != nil {
			return err
		}
		if len(sites) == 0 {
			break
		}
		stripped := false
		for _, site := range sites {
			ptr, ok := containerPointer(site.Parent)
			if !ok {
				continue
			}
			if _, done := strippedParents[ptr]; done {
				continue
			}
			strippedParents[ptr] = struct{}{}
			if err := adapter.StripDigestContainer(site); err != nil {
				return err
			}
			stripped = true
			break
		}
		if !stripped {
			break
		}
	}
	return nil
}

// containerPointer returns the Go pointer identity of a redaction-site
// parent (map or slice) for use as a comparable dedup key. Maps are not
// comparable as values, so pointer identity is the only sound way to
// distinguish "same container" across successive site enumerations.
func containerPointer(container any) (uintptr, bool) {
	switch c := container.(type) {
	case map[string]any:
		return reflect.ValueOf(c).Pointer(), true
	case map[any]any:
		return reflect.ValueOf(c).Pointer(), true
	case []any:
		return reflect.ValueOf(c).Pointer(), true
	default:
		return 0, false
	}
}
