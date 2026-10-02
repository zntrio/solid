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
	"encoding/base64"
	"fmt"
	"time"

	piondtls "github.com/pion/dtls/v3"
	"github.com/plgd-dev/go-coap/v3/dtls"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"

	"zntr.io/solid/sdk/ace"
)

// clientConfig carries the addresses and credentials of the ACE client
// role for the demo flow.
type clientConfig struct {
	asAddr   string
	rsAddr   string
	clientID string
	pki      *settings
}

// runClient executes the full ACE triangle (RFC 9200): token request
// over mutual DTLS at the AS (section 5.8), authz-info upload at the RS
// (section 5.10.1), then the protected resource access (section 5.10.2).
// It returns the final resource payload.
//
//nolint:funlen,gocyclo // linear demo flow: token → authz-info → resource
func runClient(ctx context.Context, cfg clientConfig) (string, error) {
	audience := "coaps://" + cfg.rsAddr
	scope := scopeTemperatureRead

	// --- 1. Token request at the AS (mutual DTLS, tls_client_auth) ---
	printf("client: dialing the AS at coaps://%s (mutual DTLS 1.2, ES256/P-256)", cfg.asAddr)
	asConn, err := dtls.Dial(cfg.asAddr, dtls.NewDTLSClientOptions(
		piondtls.WithCertificates(toTLSCertificate(cfg.pki.client)),
		piondtls.WithRootCAs(cfg.pki.caPool),
		piondtls.WithExtendedMasterSecret(piondtls.RequireExtendedMasterSecret),
		piondtls.WithInsecureSkipVerify(false),
	))
	if err != nil {
		return "", fmt.Errorf("unable to dial the AS: %w", err)
	}
	defer func() { _ = asConn.Close() }()

	tokenCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	printf("client: POST /token (application/ace+cbor, grant client_credentials, audience %s, scope %s)", audience, scope)
	tokenResp, err := asConn.Post(tokenCtx, "/token", message.MediaType(ace.ContentFormatACECBOR),
		bytes.NewReader(ace.EncodeTokenRequest(cfg.clientID, audience, scope)))
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	tokenBody, err := tokenResp.ReadBody()
	if err != nil {
		return "", fmt.Errorf("unable to read token response: %w", err)
	}
	if tokenResp.Code() != codes.Created {
		if e, derr := ace.DecodeTokenResponse(tokenBody); derr == nil && e.Error != nil {
			return "", fmt.Errorf("token endpoint rejected the request: code %d (%s)", e.Error.Code, e.Error.Description)
		}
		return "", fmt.Errorf("unexpected token response code %d", tokenResp.Code())
	}
	if cf, cfErr := tokenResp.ContentFormat(); cfErr != nil || cf != message.MediaType(ace.ContentFormatACECBOR) {
		return "", fmt.Errorf("unexpected token response content format %d", cf)
	}
	accessInfo, err := ace.DecodeTokenResponse(tokenBody)
	if err != nil {
		return "", fmt.Errorf("malformed Access Information: %w", err)
	}
	printf("client: access token received (%d bytes, expires in %ds, token_type=%d PoP, ace_profile=%d coap_dtls, cnf kid=%s)",
		len(accessInfo.AccessToken), accessInfo.ExpiresIn, accessInfo.TokenType, accessInfo.AceProfile,
		base64.RawURLEncoding.EncodeToString(accessInfo.Cnf.KID))

	// --- 2. authz-info at the RS (section 5.10.1) ---
	printf("client: dialing the RS at coaps://%s (mutual DTLS 1.2, ES256/P-256)", cfg.rsAddr)
	rsConn, err := dtls.Dial(cfg.rsAddr, dtls.NewDTLSClientOptions(
		piondtls.WithCertificates(toTLSCertificate(cfg.pki.client)),
		piondtls.WithRootCAs(cfg.pki.caPool),
		piondtls.WithExtendedMasterSecret(piondtls.RequireExtendedMasterSecret),
		piondtls.WithInsecureSkipVerify(false),
	))
	if err != nil {
		return "", fmt.Errorf("unable to dial the RS: %w", err)
	}
	defer func() { _ = rsConn.Close() }()

	authzCtx, cancel2 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel2()
	printf("client: POST /authz-info (raw token payload)")
	authzResp, err := rsConn.Post(authzCtx, "/authz-info", message.AppOctets, bytes.NewReader(accessInfo.AccessToken))
	if err != nil {
		return "", fmt.Errorf("authz-info request failed: %w", err)
	}
	if authzResp.Code() != codes.Created {
		body, _ := authzResp.ReadBody()
		if e, derr := ace.DecodeTokenResponse(body); derr == nil && e.Error != nil {
			return "", fmt.Errorf("authz-info rejected: code %d (%s)", e.Error.Code, e.Error.Description)
		}
		return "", fmt.Errorf("unexpected authz-info response code %d", authzResp.Code())
	}
	printf("client: token accepted by the RS (2.01 Created)")

	// --- 3. Protected resource access on the same authenticated channel ---
	getCtx, cancel3 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel3()
	printf("client: GET /temperature")
	resResp, err := rsConn.Get(getCtx, "/temperature")
	if err != nil {
		return "", fmt.Errorf("resource request failed: %w", err)
	}
	resBody, err := resResp.ReadBody()
	if err != nil {
		return "", fmt.Errorf("unable to read resource response: %w", err)
	}
	if resResp.Code() != codes.Content {
		return "", fmt.Errorf("resource access denied: code %d body %s", resResp.Code(), resBody)
	}
	printf("client: resource response (2.05 Content, application/json): %s", resBody)

	return string(resBody), nil
}
