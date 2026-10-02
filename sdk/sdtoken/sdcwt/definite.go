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

package sdcwt

import (
	"fmt"
)

// checkDefiniteLength structurally rejects any indefinite-length CBOR
// item (major types 2-5 with additional-info 31, and the 0xff break
// code; draft section 5.1 forbids indefinite lengths entirely in
// SD-CWT). It also validates overall structural well-formedness.

func checkDefiniteLength(raw []byte) error {
	end, err := scanItem(raw, 0, 0)
	if err != nil {
		return err
	}
	if end != len(raw) {
		return fmt.Errorf("%w: trailing garbage after the first item", ErrInvalidSDCWT)
	}
	return nil
}

// scanItem returns the offset just past the CBOR item starting at
// offset i in raw. depth guards against pathological nesting.
func scanItem(raw []byte, i, depth int) (int, error) {
	if depth > maxClaimsDepth+8 {
		return 0, fmt.Errorf("%w: nesting too deep", ErrInvalidSDCWT)
	}
	if i >= len(raw) {
		return 0, fmt.Errorf("%w: truncated item", ErrInvalidSDCWT)
	}

	head, err := scanItemHead(raw, i)
	if err != nil {
		return 0, err
	}

	switch head.major {
	case 0, 1, 7:
		// Integers and simple values: no content.
		return head.next, nil
	case 2, 3:
		return scanStringLength(head, i)
	case 4:
		return scanContainer(raw, head, i, depth, head.arg)
	case 5:
		return scanContainer(raw, head, i, depth, 2*head.arg)
	case 6:
		// Tag: one tagged item follows.
		return scanItem(raw, head.next, depth+1)
	default:
		return 0, fmt.Errorf("%w: invalid major type at offset %d", ErrInvalidSDCWT, i)
	}
}

// itemHead is the decoded head of a CBOR item: the major type, the
// argument, the offset just past the head, and the input remaining
// after it.
type itemHead struct {
	major     byte
	arg       uint64
	next      int
	remaining int
}

// scanItemHead decodes the initial byte and argument of the item at
// offset i, rejecting break codes and indefinite lengths (draft
// section 5.1).
func scanItemHead(raw []byte, i int) (itemHead, error) {
	b := raw[i]
	major := b >> 5
	additional := b & 0x1f

	// Break code (0xff): only legal as an indefinite-container
	// terminator, and indefinite containers are forbidden — reject.
	if b == 0xff {
		return itemHead{}, fmt.Errorf("%w: indefinite-length break code at offset %d", ErrInvalidSDCWT, i)
	}

	// Indefinite-length containers and strings.
	if additional == 0x1f {
		return itemHead{}, fmt.Errorf("%w: indefinite-length item at offset %d", ErrInvalidSDCWT, i)
	}

	// Argument length.
	argLen := 0
	switch {
	case additional < 24:
		// Argument inlined in the additional info.
	case additional == 24:
		argLen = 1
	case additional == 25:
		argLen = 2
	case additional == 26:
		argLen = 4
	case additional == 27:
		argLen = 8
	}
	if i+1+argLen > len(raw) {
		return itemHead{}, fmt.Errorf("%w: truncated argument at offset %d", ErrInvalidSDCWT, i)
	}
	next := i + 1 + argLen
	remaining := len(raw) - next
	if remaining < 0 {
		remaining = 0
	}
	return itemHead{
		major:     major,
		arg:       decodeArgument(raw[i+1:i+1+argLen], additional),
		next:      next,
		remaining: remaining,
	}, nil
}

// scanStringLength consumes a definite-length byte/text string.
func scanStringLength(head itemHead, i int) (int, error) {
	// The length cannot exceed the remaining input.
	if head.arg > uint64(head.remaining) { // #nosec G115 -- remaining is a non-negative slice length delta
		return 0, fmt.Errorf("%w: truncated string at offset %d", ErrInvalidSDCWT, i)
	}
	return head.next + int(head.arg), nil // #nosec G115 -- bounded by the remaining-length guard above
}

// scanContainer consumes an array (major 4) or map (major 5): count
// items follow the head. Each item consumes at least one byte, so a
// count beyond the remaining input is necessarily truncated — this
// bounds the count before any int conversion (guards against hostile
// overflow arguments).
func scanContainer(raw []byte, head itemHead, i, depth int, count uint64) (int, error) {
	if count > uint64(head.remaining) { // #nosec G115 -- remaining is a non-negative slice length delta
		return 0, fmt.Errorf("%w: truncated container at offset %d", ErrInvalidSDCWT, i)
	}
	next := head.next
	for range count {
		n, err := scanItem(raw, next, depth+1)
		if err != nil {
			return 0, err
		}
		next = n
	}
	return next, nil
}

// decodeArgument decodes a CBOR argument from its big-endian bytes
// (argBytes may be empty when the argument is inlined).
func decodeArgument(argBytes []byte, additional byte) uint64 {
	if len(argBytes) == 0 {
		return uint64(additional)
	}
	var v uint64
	for _, b := range argBytes {
		v = v<<8 | uint64(b)
	}
	return v
}
