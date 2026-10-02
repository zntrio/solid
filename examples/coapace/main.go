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

// Command coapace demonstrates OAuth 2.0 over CoAP per RFC 9200
// (ACE-OAuth): a client obtains a certificate-bound access token from
// an Authorization Server over mutual DTLS 1.2, uploads it to a
// Resource Server at /authz-info, and accesses a protected resource —
// all three roles assembled in one process (or run separately with the
// as/rs/client subcommands).
//
// The wire codec is sdk/ace (application/ace+cbor); the AS reuses the
// presentation-agnostic token and introspection services and the
// RFC 8705 tls_client_auth processor from server/, with zero protocol
// changes. The binding is mTLS certificate-based (coap_dtls profile,
// RFC 9202): no DPoP on the CoAP side by design.
package main

import (
	"context"
	"fmt"
	"os"
	"time"
)

func printf(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}

// Demo addresses (loopback; 5684 is the standard coaps port).
const (
	demoASAddr = "127.0.0.1:5684"
	demoRSAddr = "127.0.0.1:5685"
)

func main() {
	// Subcommand dispatch: default runs the full in-process triangle.
	switch {
	case len(os.Args) > 1 && os.Args[1] == "as":
		runStandaloneAS()
		return
	case len(os.Args) > 1 && os.Args[1] == "rs":
		runStandaloneRS()
		return
	case len(os.Args) > 1 && os.Args[1] == "client":
		runStandaloneClient()
		return
	}

	printf("=== SolID ACE-OAuth (RFC 9200) over mutual DTLS 1.2 demo ===")
	printf("")

	pki, err := newSettings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to generate demo PKI: %v\n", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	printf("--- Authorization Server (coaps://%s, ES256/P-256, tls_client_auth) ---", demoASAddr)
	as, err := startAS(pki, demoASAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to start the AS: %v\n", err)
		return
	}
	printf("as: token endpoint /token, introspection endpoint /introspect")
	printf("as: registered demo client %s (SAN URI %s) and RS %s (SAN URI %s)", as.clientID, clientSanURI, as.rsID, rsSanURI)
	printf("")

	printf("--- Resource Server (coaps://%s, introspection at the AS) ---", demoRSAddr)
	if rsErr := startRS(pki, demoASAddr, demoRSAddr); rsErr != nil {
		fmt.Fprintf(os.Stderr, "unable to start the RS: %v\n", rsErr)
		return
	}
	printf("rs: authz-info endpoint /authz-info, protected resource /temperature")
	printf("")

	// Let the UDP listeners settle (DTLS handshake readiness).
	time.Sleep(200 * time.Millisecond)

	printf("--- Client (token → authz-info → resource) ---")
	payload, err := runClient(ctx, clientConfig{
		asAddr:   demoASAddr,
		rsAddr:   demoRSAddr,
		clientID: as.clientID,
		pki:      pki,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo failed: %v\n", err)
		return
	}
	printf("")
	printf("=== demo complete: resource payload %s ===", payload)
}

// runStandaloneAS runs only the AS (split mode, coaps://127.0.0.1:5684).
func runStandaloneAS() {
	pki, err := newSettings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to generate demo PKI: %v\n", err)
		os.Exit(1)
	}
	if _, err := startAS(pki, demoASAddr); err != nil {
		fmt.Fprintf(os.Stderr, "unable to start the AS: %v\n", err)
		os.Exit(1)
	}
	printf("as: listening on coaps://%s (key material and client identifiers are ephemeral per boot)", demoASAddr)
	select {}
}

// runStandaloneRS runs only the RS (split mode, coaps://127.0.0.1:5685).
func runStandaloneRS() {
	pki, err := newSettings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to generate demo PKI: %v\n", err)
		os.Exit(1)
	}
	if rsErr := startRS(pki, demoASAddr, demoRSAddr); rsErr != nil {
		fmt.Fprintf(os.Stderr, "unable to start the RS: %v\n", rsErr)
		return
	}
	printf("rs: listening on coaps://%s", demoRSAddr)
	select {}
}

// runStandaloneClient documents the split-mode boundary: the demo PKI
// is ephemeral per boot, so the client cannot share credentials with
// separately started processes. Use the all-in-one demo for the
// runnable triangle.
func runStandaloneClient() {
	fmt.Fprintln(os.Stderr, "client: split mode is not runnable with ephemeral per-boot keys; use `go run ./examples/coapace` for the full triangle")
	os.Exit(1)
}
