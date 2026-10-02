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

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	piondtls "github.com/pion/dtls/v3"
	"github.com/plgd-dev/go-coap/v3/dtls"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"
	"github.com/plgd-dev/go-coap/v3/net"
	"github.com/plgd-dev/go-coap/v3/options"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/ace"
	sdktoken "zntr.io/solid/sdk/token"
)

// resourceServer assembles the ACE RS over mutual DTLS: /authz-info
// (RFC 9200 section 5.10.1) and the protected /temperature resource,
// with introspection-based token validation at the AS (section 5.9).
type resourceServer struct {
	asAddr   string // AS address for the introspection back-channel
	audience string // this RS identifier (audience of accepted tokens)
	pki      *settings

	mu    sync.Mutex
	bound map[string]*tokenv1.Token // x5t#S256 → token (one per PoP key, section 5.10.1)
}

// startRS runs the RS DTLS listener on rsAddr, introspecting tokens at
// the AS at asAddr.
func startRS(pki *settings, asAddr, rsAddr string) error {
	rs := &resourceServer{
		asAddr:   asAddr,
		audience: "coaps://" + rsAddr,
		pki:      pki,
		bound:    map[string]*tokenv1.Token{},
	}

	router := mux.NewRouter()
	router.HandleFunc("/authz-info", rs.handleAuthzInfo)
	router.HandleFunc("/temperature", rs.handleTemperature)

	listener, err := net.NewDTLSListener("udp", rsAddr, net.NewDTLSServerOptions(
		piondtls.WithCertificates(toTLSCertificate(pki.rsCert)),
		piondtls.WithClientCAs(pki.caPool),
		piondtls.WithClientAuth(piondtls.RequireAndVerifyClientCert),
		piondtls.WithExtendedMasterSecret(piondtls.RequireExtendedMasterSecret),
	))
	if err != nil {
		return fmt.Errorf("unable to open RS DTLS listener: %w", err)
	}
	go func() {
		_ = dtls.NewServer(options.WithMux(router)).Serve(listener) // returns on close
	}()
	return nil
}

// handleAuthzInfo implements RFC 9200 section 5.10.1: the client POSTs
// the raw access token; the RS validates it by introspection at the AS
// and stores it keyed by the confirmation PoP reference (one token per
// PoP key: a new upload supersedes the previous one).
func (rs *resourceServer) handleAuthzInfo(w mux.ResponseWriter, r *mux.Message) {
	// Section 5.10.1.2: POST only; other methods → 4.05.
	if r.Code() != codes.POST {
		if err := w.SetResponse(codes.MethodNotAllowed, message.TextPlain, nil); err != nil {
			printf("rs: cannot write 4.05: %v", err)
		}
		return
	}
	// The token is carried as the raw request payload (octet-stream
	// semantics, section 5.10.1).
	body, err := r.ReadBody()
	if err != nil || len(body) == 0 {
		writeACEError(w, codes.BadRequest, ace.ErrInvalidRequest, "empty authz-info payload")
		return
	}

	// The RS must know the client certificate that presented the token
	// (the DTLS channel is mutually authenticated).
	peerCert, ok := peerCertificate(w)
	if !ok {
		writeACEError(w, codes.Unauthorized, ace.ErrInvalidClient, "no client certificate on the DTLS channel")
		return
	}

	// Validate the token at the AS (introspection, section 5.9): active,
	// audience-restricted to this RS, carrying the x5t confirmation of
	// the presenting client's certificate.
	res, err := rs.introspect(r.Context(), body)
	if err != nil {
		writeACEError(w, codes.BadRequest, ace.ErrInvalidRequest, "unable to validate token at the AS")
		return
	}
	if !res.Active {
		writeACEError(w, codes.Unauthorized, ace.ErrInvalidGrant, "token is not active")
		return
	}
	if res.Cnf == nil || res.Cnf.KID == nil || len(res.Cnf.KID) == 0 {
		writeACEError(w, codes.Unauthorized, ace.ErrInvalidGrant, "token carries no key confirmation")
		return
	}

	// The confirmation must reference the presenting certificate's
	// thumbprint: certificate binding (RFC 8705 section 3 via the
	// introspected x5t#S256 reference).
	peerX5T := sdktoken.X509ThumbprintS256(peerCert)
	if peerX5T != string(res.Cnf.KID) {
		writeACEError(w, codes.Unauthorized, ace.ErrInvalidGrant, "token is bound to another key")
		return
	}

	// Scope enforcement for the protected resource: exact space-delimited
	// token membership, not substring (a "temperature:readonly"-style
	// scope must not match).
	if !slices.Contains(strings.Fields(res.Scope), scopeTemperatureRead) {
		writeACEError(w, codes.Forbidden, ace.ErrInvalidScope, scopeTemperatureRead+" scope required")
		return
	}

	// Store keyed by the PoP reference (section 5.10.1: RECOMMENDED one
	// token per proof-of-possession key; a new upload supersedes).
	rs.mu.Lock()
	rs.bound[peerX5T] = &tokenv1.Token{
		Value:        string(body),
		Status:       tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE,
		Confirmation: &tokenv1.TokenConfirmation{X5TS256: peerX5T},
		Metadata: &tokenv1.TokenMeta{
			Scope:     res.Scope,
			ExpiresAt: res.Exp,
		},
	}
	rs.mu.Unlock()

	// 2.01 Created: the token was accepted.
	if err := w.SetResponse(codes.Created, message.TextPlain, nil); err != nil {
		printf("rs: cannot write authz-info response: %v", err)
	}
}

// handleTemperature serves the protected resource: the request must
// arrive on the mutually-DTLS-authenticated channel whose certificate
// owns a stored token (RFC 9200 section 5.10.2 enforcement).
func (rs *resourceServer) handleTemperature(w mux.ResponseWriter, r *mux.Message) {
	if r.Code() != codes.GET {
		if err := w.SetResponse(codes.MethodNotAllowed, message.TextPlain, nil); err != nil {
			printf("rs: cannot write 4.05: %v", err)
		}
		return
	}

	peerCert, ok := peerCertificate(w)
	if !ok {
		// 4.01 with AS Request Creation Hints (section 5.3, Table 1).
		writeHints(w, rs.asAddr, rs.audience)
		return
	}
	x5t := sdktoken.X509ThumbprintS256(peerCert)

	rs.mu.Lock()
	t, found := rs.bound[x5t]
	rs.mu.Unlock()
	if !found || t == nil {
		// Unknown key: 4.01 with AS Request Creation Hints (section 5.10.2).
		writeHints(w, rs.asAddr, rs.audience)
		return
	}
	// Expiration: the introspection already gated upload; re-check the
	// stored expiry defensively.
	if t.Metadata != nil && t.Metadata.ExpiresAt <= uint64(time.Now().Unix()) { //nolint:gosec // unix time is non-negative
		writeHints(w, rs.asAddr, rs.audience)
		return
	}
	// Per-request certificate binding check (RFC 8705 section 3).
	if !sdktoken.CertificateBound(t.Confirmation, []*x509.Certificate{peerCert}) {
		writeHints(w, rs.asAddr, rs.audience)
		return
	}

	// 2.05 Content with the resource representation.
	payload, _ := json.Marshal(map[string]any{"temperature": 22.5, "unit": "C"})
	if err := w.SetResponse(codes.Content, message.AppJSON, bytes.NewReader(payload)); err != nil {
		printf("rs: cannot write temperature response: %v", err)
	}
}

// writeHints responds 4.01 with AS Request Creation Hints (RFC 9200
// section 5.3 Table 1 payload, application/ace+cbor).
func writeHints(w mux.ResponseWriter, asAddr, audience string) {
	hints := ace.EncodeASRequestCreationHints("coaps://"+asAddr+"/token", audience, scopeTemperatureRead)
	if err := w.SetResponse(codes.Unauthorized, message.MediaType(ace.ContentFormatACECBOR), bytes.NewReader(hints)); err != nil {
		printf("rs: cannot write hints response: %v", err)
	}
}

// introspect calls the AS /introspect endpoint over the RS's own DTLS
// connection (mutually authenticated with the RS certificate).
func (rs *resourceServer) introspect(ctx context.Context, tokenValue []byte) (*ace.IntrospectionResponse, error) {
	conn, err := dtls.Dial(rs.asAddr, dtls.NewDTLSClientOptions(
		piondtls.WithCertificates(toTLSCertificate(rs.pki.rsCert)),
		piondtls.WithRootCAs(rs.pki.caPool),
		piondtls.WithExtendedMasterSecret(piondtls.RequireExtendedMasterSecret),
		piondtls.WithInsecureSkipVerify(false),
	))
	if err != nil {
		return nil, fmt.Errorf("unable to dial the AS: %w", err)
	}
	defer func() { _ = conn.Close() }()

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := conn.Post(dialCtx, "/introspect", message.MediaType(ace.ContentFormatACECBOR), bytes.NewReader(ace.EncodeIntrospectionRequest(tokenValue, 0)))
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	if resp.Code() != codes.Content {
		return nil, fmt.Errorf("unexpected introspection response code %d", resp.Code())
	}
	body, err := resp.ReadBody()
	if err != nil {
		return nil, fmt.Errorf("unable to read introspection response: %w", err)
	}
	return ace.DecodeIntrospectionResponse(body)
}
