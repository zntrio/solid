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

// Package flowlog provides an http.RoundTripper that prints the OAuth
// protocol flow — every request and response — to stdout, with token,
// proof, and assertion values redacted for readability. Example clients
// install it to make the exchanged messages observable.
package flowlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// headersRedacted lists request headers whose long cryptographic values
// (client assertions, DPoP proofs, access tokens) are truncated in output.
var headersRedacted = map[string]bool{
	"Authorization":                true,
	"Dpop":                         true,
	"OAuth-Client-Attestation":     true,
	"OAuth-Client-Attestation-Pop": true,
}

// bodyLimit caps how much of a response body is printed.
const bodyLimit = 4 << 10 // 4 KiB

// New returns an *http.Client whose transport prints each request and its
// response, with cryptographic values truncated for readability. It is
// ready to be passed as client.Options.HTTPClient or used directly.
func New() *http.Client {
	return &http.Client{Transport: roundTripperFunc(roundTrip)}
}

// roundTripperFunc adapts a function to the http.RoundTripper interface.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func roundTrip(req *http.Request) (*http.Response, error) {
	fmt.Printf("→ %s %s\n", req.Method, req.URL)

	// Request headers, redacting the cryptographic ones.
	for name, values := range req.Header {
		for _, v := range values {
			if headersRedacted[http.CanonicalHeaderKey(name)] && len(v) > 48 {
				fmt.Printf("  %s: %s…(+%d bytes)\n", name, v[:48], len(v)-48)
			} else {
				fmt.Printf("  %s: %s\n", name, v)
			}
		}
	}

	// Request body: form parameters print field by field with token-like
	// values truncated; everything else prints raw (bounded).
	var res *http.Response
	var err error
	if req.Body != nil && req.Body != http.NoBody {
		// Read the full body: it must be restored intact for the real
		// transport; only the printed copy is bounded.
		body, readErr := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		printRequestBody(req, body)
	}
	res, err = http.DefaultTransport.RoundTrip(req)
	if err != nil {
		fmt.Printf("  ! transport error: %v\n", err)
		return nil, err
	}

	// Response line and headers.
	fmt.Printf("← HTTP %d\n", res.StatusCode)
	for name, values := range res.Header {
		for _, v := range values {
			fmt.Printf("  %s: %s\n", name, v)
		}
	}

	// Response body is fully buffered — restored intact for the caller —
	// while the printed copy is bounded and truncated for readability.
	body, readErr := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) > 0 {
		if isRedactableJSON(body) {
			printRedactedJSON(body)
		} else {
			fmt.Printf("  %s\n", clip(body))
		}
	}

	fmt.Println()
	return res, nil
}

// printRequestBody prints a request body. Form-encoded bodies print one
// parameter per line with assertion/proof/token values truncated; other
// content types print the raw body.
func printRequestBody(req *http.Request, body []byte) {
	ct := req.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		for _, pair := range strings.Split(string(body), "&") {
			k, v, _ := strings.Cut(pair, "=")
			if isSecretParam(k) && len(v) > 48 {
				fmt.Printf("  %s=%s…(+%d bytes)\n", k, v[:48], len(v)-48)
			} else {
				fmt.Printf("  %s=%s\n", k, v)
			}
		}
		return
	}
	if len(body) > 0 {
		fmt.Printf("  %s\n", string(body))
	}
}

// isSecretParam reports whether a form parameter carries a long
// cryptographic value (client assertion, request object, or token).
func isSecretParam(key string) bool {
	switch key {
	case "client_assertion", "request", "token":
		return true
	}
	return false
}

// isRedactableJSON reports whether the body looks like a JSON object
// whose token-like members should be truncated before printing.
func isRedactableJSON(body []byte) bool {
	s := strings.TrimSpace(string(body))
	return strings.HasPrefix(s, "{")
}

// jsonRedactKeys lists JSON response members truncated in output.
var jsonRedactKeys = map[string]bool{
	"access_token":  true,
	"refresh_token": true,
}

func printRedactedJSON(body []byte) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var obj map[string]json.RawMessage
	if err := dec.Decode(&obj); err != nil {
		// Not a flat JSON object (arrays, scalars, NDJSON): print raw.
		fmt.Printf("  %s\n", clip(body))
		return
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := strings.TrimSpace(string(obj[k]))
		if jsonRedactKeys[k] && len(v) > 48 {
			fmt.Printf("  %q: %s…(+%d bytes)\n", k, v[:48], len(v)-48)
		} else {
			fmt.Printf("  %q: %s\n", k, v)
		}
	}
}

// clip bounds a raw body copy to bodyLimit bytes with an ellipsis marker.
func clip(body []byte) string {
	if len(body) <= bodyLimit {
		return string(body)
	}
	return string(body[:bodyLimit]) + fmt.Sprintf("…(+%d bytes)", len(body)-bodyLimit)
}
