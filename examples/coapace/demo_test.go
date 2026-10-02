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
	"crypto/x509/pkix"
	"encoding/json"
	"net"
	"testing"
	"time"

	piondtls "github.com/pion/dtls/v3"
	"github.com/plgd-dev/go-coap/v3/dtls"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	udpClient "github.com/plgd-dev/go-coap/v3/udp/client"

	"zntr.io/solid/sdk/ace"
)

// freeUDPPort reserves an ephemeral loopback UDP port for the demo
// listeners (DTLS over UDP).
func freeUDPPort(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to reserve UDP port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().String()
}

// TestCoAPACEDemo runs the full in-process ACE triangle (AS + RS +
// client) over mutual DTLS and asserts the observable behavior of every
// step, including the negative paths.
func TestCoAPACEDemo(t *testing.T) {
	pki, err := newSettings()
	if err != nil {
		t.Fatalf("unable to generate demo PKI: %v", err)
	}

	asAddr := freeUDPPort(t)
	rsAddr := freeUDPPort(t)

	as, err := startAS(pki, asAddr)
	if err != nil {
		t.Fatalf("unable to start the AS: %v", err)
	}
	if err := startRS(pki, asAddr, rsAddr); err != nil {
		t.Fatalf("unable to start the RS: %v", err)
	}
	// UDP/DTLS listener settle time.
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// --- Happy path: token → authz-info → temperature ---
	accessToken := fetchToken(t, ctx, pki, asAddr, rsAddr, as.clientID)
	uploadAuthzInfo(t, ctx, pki, rsAddr, accessToken)
	body := getTemperature(t, ctx, pki, rsAddr, true)
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("resource payload is not JSON: %v", err)
	}
	if payload["temperature"] != 22.5 || payload["unit"] != "C" {
		t.Errorf("unexpected resource payload: %s", body)
	}

	// --- Negative: wrong client_id → 4.01 invalid_client (error=2) ---
	t.Run("wrong client id", func(t *testing.T) {
		conn := dialDTLS(t, ctx, pki, asAddr)
		defer conn.Close()
		req := ace.EncodeTokenRequest("not-a-registered-client", "coaps://"+rsAddr, scopeTemperatureRead)
		resp, err := conn.Post(ctx, "/token", message.MediaType(ace.ContentFormatACECBOR), bytes.NewReader(req))
		if err != nil {
			t.Fatalf("token request failed: %v", err)
		}
		if resp.Code() != codes.Unauthorized {
			t.Errorf("response code = %d, want 4.01", resp.Code())
		}
		body, _ := resp.ReadBody()
		res, derr := ace.DecodeTokenResponse(body)
		if derr != nil || res.Error == nil {
			t.Fatalf("expected error payload, got %s", body)
		}
		if res.Error.Code != ace.ErrInvalidClient {
			t.Errorf("error code = %d, want %d (invalid_client)", res.Error.Code, ace.ErrInvalidClient)
		}
	})

	// --- Negative: GET /temperature with a token but a different,
	// unregistered certificate (second client, no stored token) → 4.01
	// with AS Request Creation Hints carrying the AS key (1). ---
	t.Run("unknown cert gets hints", func(t *testing.T) {
		// Register a second client bound to a fresh certificate.
		secondCert, err := newLeaf(pki.caCert, pki.caKey, &pkix.Name{CommonName: "coap-ace-second-client"}, nil, clientSanURI)
		if err != nil {
			t.Fatalf("unable to issue second client certificate: %v", err)
		}
		cfg := &settings{caPool: pki.caPool, client: secondCert}

		conn, err := dtls.Dial(rsAddr, dtls.NewDTLSClientOptions(
			piondtls.WithCertificates(toTLSCertificate(cfg.client)),
			piondtls.WithRootCAs(cfg.caPool),
			piondtls.WithExtendedMasterSecret(piondtls.RequireExtendedMasterSecret),
			piondtls.WithInsecureSkipVerify(false),
		))
		if err != nil {
			t.Fatalf("unable to dial the RS: %v", err)
		}
		defer conn.Close()

		resp, err := conn.Get(ctx, "/temperature")
		if err != nil {
			t.Fatalf("resource request failed: %v", err)
		}
		if resp.Code() != codes.Unauthorized {
			t.Errorf("response code = %d, want 4.01", resp.Code())
		}
		body, err := resp.ReadBody()
		if err != nil {
			t.Fatalf("unable to read hints payload: %v", err)
		}
		hints, err := ace.DecodeTokenRequest(body)
		if err == nil && hints.ClientID != "" {
			t.Fatalf("hints payload decoded as a token request: %s", body)
		}
		// Raw check: the hints payload contains the AS endpoint reference.
		if !bytes.Contains(body, []byte("coaps://"+asAddr+"/token")) {
			t.Errorf("hints payload does not reference the AS endpoint: %x", body)
		}
	})

	// --- Negative: authz-info with a foreign token (never issued) → 4.01
	// invalid_grant, no storage ---
	t.Run("foreign token rejected", func(t *testing.T) {
		conn := dialDTLS(t, ctx, pki, rsAddr)
		defer conn.Close()
		resp, err := conn.Post(ctx, "/authz-info", message.AppOctets, bytes.NewReader([]byte("forged-token-value")))
		if err != nil {
			t.Fatalf("authz-info request failed: %v", err)
		}
		if resp.Code() != codes.Unauthorized {
			t.Errorf("response code = %d, want 4.01", resp.Code())
		}
		body, _ := resp.ReadBody()
		res, derr := ace.DecodeTokenResponse(body)
		if derr != nil || res.Error == nil {
			t.Fatalf("expected error payload, got %s", body)
		}
		if res.Error.Code != ace.ErrInvalidGrant {
			t.Errorf("error code = %d, want %d (invalid_grant)", res.Error.Code, ace.ErrInvalidGrant)
		}
	})

	// --- Negative: token request with wrong content format → 4.00 ---
	t.Run("wrong content format", func(t *testing.T) {
		conn := dialDTLS(t, ctx, pki, asAddr)
		defer conn.Close()
		resp, err := conn.Post(ctx, "/token", message.TextPlain, bytes.NewReader([]byte("not-cbor")))
		if err != nil {
			t.Fatalf("token request failed: %v", err)
		}
		if resp.Code() != codes.BadRequest {
			t.Errorf("response code = %d, want 4.00", resp.Code())
		}
	})
}

// fetchToken runs the client token request and asserts the Access
// Information invariants, returning the opaque token bytes.
func fetchToken(t *testing.T, ctx context.Context, pki *settings, asAddr, rsAddr, clientID string) []byte {
	t.Helper()
	conn := dialDTLS(t, ctx, pki, asAddr)
	defer conn.Close()

	req := ace.EncodeTokenRequest(clientID, "coaps://"+rsAddr, scopeTemperatureRead)
	resp, err := conn.Post(ctx, "/token", message.MediaType(ace.ContentFormatACECBOR), bytes.NewReader(req))
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	if resp.Code() != codes.Created {
		body, _ := resp.ReadBody()
		t.Fatalf("token response code = %d, want 2.01; body %s", resp.Code(), body)
	}
	if cf, cfErr := resp.ContentFormat(); cfErr != nil || cf != message.MediaType(ace.ContentFormatACECBOR) {
		t.Fatalf("token response content format = %d, want 19", cf)
	}
	body, err := resp.ReadBody()
	if err != nil {
		t.Fatalf("unable to read token response: %v", err)
	}
	res, err := ace.DecodeTokenResponse(body)
	if err != nil {
		t.Fatalf("malformed Access Information: %v", err)
	}
	if len(res.AccessToken) == 0 {
		t.Fatal("access token is empty")
	}
	if res.ExpiresIn == 0 {
		t.Fatal("expires_in is zero")
	}
	if res.TokenType != ace.TokenTypePoP {
		t.Errorf("token_type = %d, want %d (PoP)", res.TokenType, ace.TokenTypePoP)
	}
	if res.AceProfile != ace.AceProfileCoapDTLS {
		t.Errorf("ace_profile = %d, want %d (coap_dtls)", res.AceProfile, ace.AceProfileCoapDTLS)
	}
	if res.Cnf == nil || len(res.Cnf.KID) == 0 {
		t.Fatal("cnf kid missing from Access Information")
	}
	return res.AccessToken
}

// uploadAuthzInfo POSTs the token at the RS /authz-info.
func uploadAuthzInfo(t *testing.T, ctx context.Context, pki *settings, rsAddr string, token []byte) {
	t.Helper()
	conn := dialDTLS(t, ctx, pki, rsAddr)
	defer conn.Close()

	resp, err := conn.Post(ctx, "/authz-info", message.AppOctets, bytes.NewReader(token))
	if err != nil {
		t.Fatalf("authz-info request failed: %v", err)
	}
	if resp.Code() != codes.Created {
		body, _ := resp.ReadBody()
		t.Fatalf("authz-info response code = %d, want 2.01; body %s", resp.Code(), body)
	}
}

// getTemperature GETs the protected resource. withToken selects whether
// the caller previously uploaded a token bound to this certificate.
func getTemperature(t *testing.T, ctx context.Context, pki *settings, rsAddr string, withToken bool) []byte {
	t.Helper()
	conn := dialDTLS(t, ctx, pki, rsAddr)
	defer conn.Close()

	resp, err := conn.Get(ctx, "/temperature")
	if err != nil {
		t.Fatalf("resource request failed: %v", err)
	}
	if withToken {
		if resp.Code() != codes.Content {
			t.Fatalf("resource response code = %d, want 2.05", resp.Code())
		}
	} else if resp.Code() != codes.Unauthorized {
		t.Fatalf("resource response code = %d, want 4.01", resp.Code())
	}
	body, err := resp.ReadBody()
	if err != nil {
		t.Fatalf("unable to read resource response: %v", err)
	}
	return body
}

// dialDTLS opens a mutual-DTLS CoAP connection with the demo client
// certificate.
func dialDTLS(t *testing.T, ctx context.Context, pki *settings, addr string) *udpClient.Conn {
	t.Helper()
	_ = ctx
	conn, err := dtls.Dial(addr, dtls.NewDTLSClientOptions(
		piondtls.WithCertificates(toTLSCertificate(pki.client)),
		piondtls.WithRootCAs(pki.caPool),
		piondtls.WithExtendedMasterSecret(piondtls.RequireExtendedMasterSecret),
		piondtls.WithInsecureSkipVerify(false),
	))
	if err != nil {
		t.Fatalf("unable to dial %s: %v", addr, err)
	}
	return conn
}
