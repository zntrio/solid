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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	piondtls "github.com/pion/dtls/v3"
	"github.com/plgd-dev/go-coap/v3/dtls"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"
	"github.com/plgd-dev/go-coap/v3/net"
	"github.com/plgd-dev/go-coap/v3/options"
	"github.com/veraison/go-cose"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/ace"
	"zntr.io/solid/sdk/jwk"
	sdktoken "zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/cwt"
	"zntr.io/solid/sdk/token/verifiable"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/services"
	"zntr.io/solid/server/services/token"
	"zntr.io/solid/server/storage"
	"zntr.io/solid/server/storage/inmemory"
)

// Certificate SAN URIs used as the RFC 8705 section 2.1.2 binding field
// (exactly one per client) for the demo registrations.
const (
	clientSanURI = "urn:coap:ace:client:demo"
	rsSanURI     = "urn:coap:ace:rs:demo"
	// scopeTemperatureRead is the protected temperature reading scope
	// carried by the demo token requests and enforced by the RS.
	scopeTemperatureRead = "temperature:read"
)

// authorizationServer assembles the ACE AS over mutual DTLS: the token
// endpoint (RFC 9200 section 5.8) and the introspection endpoint
// (section 5.9), both authenticated with the DTLS client certificate
// (RFC 8705 tls_client_auth via clientauthentication.TLSClientAuth).
type authorizationServer struct {
	issuer        string
	tokens        services.Token
	clients       storage.Client
	authenticator clientauthentication.AuthenticationProcessor
	pki           *settings
	clientID      string // registered demo client identifier
	rsID          string // registered RS introspection caller identifier
}

// startAS assembles the AS services and starts the DTLS listener. It
// returns after client registration so the caller can thread the
// identifiers (the demo client token carries AuthorizedIntrospectionClients
// = [rsID], RFC 7662 section 2.1).
func startAS(pki *settings, asAddr string) (*authorizationServer, error) {
	issuer := "coaps://" + asAddr
	ctx := context.Background()

	// Storage (in-memory, ephemeral): the token service constructor
	// requires the full set even though client_credentials only uses
	// clients + tokens.
	storageKey := make([]byte, 32)
	if _, err := rand.Read(storageKey); err != nil {
		return nil, fmt.Errorf("unable to generate storage key: %w", err)
	}
	clients := inmemory.Clients()
	authSessions := inmemory.AuthorizationCodeSessions(storageKey)
	deviceSessions := inmemory.DeviceCodeSessions(storageKey)
	backchannelSessions := inmemory.BackchannelAuthenticationSessions(storageKey)
	tokensStorage := inmemory.Tokens(storageKey)
	resources := inmemory.Resources()

	// Token generators. SOLID_EXAMPLE_TOKEN_FORMAT selects the
	// serialization format of issued tokens (default "opaque"):
	//   - opaque: verifiable (signed UUIDv7) reference tokens — the
	//     SDK's opaque reference-token model;
	//   - cwt: RFC 8392 CBOR Web Tokens signed with an ephemeral ES256 key.
	// Introspection is value-agnostic (the token service resolves tokens by
	// stored string value), so the RS and client code is identical in both
	// modes.
	var accessTokens, refreshTokens sdktoken.Generator
	switch os.Getenv("SOLID_EXAMPLE_TOKEN_FORMAT") {
	case "cwt":
		cwtKey, err := cwtSigningKey()
		if err != nil {
			return nil, fmt.Errorf("unable to prepare CWT signing key: %w", err)
		}
		keyProvider := jwk.KeyProviderFunc(func(_ context.Context) (jwk.Key, error) {
			return cwtKey, nil
		})
		accessTokens = sdktoken.AccessToken(cwt.AccessTokenSigner(cose.AlgorithmES256, keyProvider))
		refreshTokens = sdktoken.RefreshToken(cwt.RefreshTokenSigner(cose.AlgorithmES256, keyProvider))
	default:
		accessTokens = verifiable.Token(verifiable.UUIDv7Source(), storageKey)
		refreshTokens = verifiable.Token(verifiable.UUIDv7Source(), storageKey)
	}

	// Presentation-agnostic token service.
	tokens := token.New(accessTokens, refreshTokens, clients, authSessions, deviceSessions, backchannelSessions, tokensStorage, resources)

	// Register the RS first (introspection caller, mTLS-authenticated, no
	// grants: TLSClientAuth only checks the auth method + binding).
	rsID, err := clients.Register(ctx, &clientv1.Client{
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:              "coap-ace-rs",
		TokenEndpointAuthMethod: oidc.AuthMethodTLSClientAuth,
		TlsClientAuthSanUri:     rsSanURI,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to register RS client: %w", err)
	}

	// Register the demo client: mTLS-bound (SAN URI, exactly one binding
	// field), client_credentials grant; the RS may introspect its tokens.
	clientID, err := clients.Register(ctx, &clientv1.Client{
		ClientType:                     clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:                     "coap-ace-client",
		GrantTypes:                     []string{oidc.GrantTypeClientCredentials},
		TokenEndpointAuthMethod:        oidc.AuthMethodTLSClientAuth,
		TlsClientAuthSanUri:            clientSanURI,
		AuthorizedIntrospectionClients: []string{rsID},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to register demo client: %w", err)
	}

	as := &authorizationServer{
		issuer:        issuer,
		pki:           pki,
		tokens:        tokens,
		clients:       clients,
		authenticator: clientauthentication.TLSClientAuth(clients),
		clientID:      clientID,
		rsID:          rsID,
	}

	// Router: /token (section 5.8) and /introspect (section 5.9).
	router := mux.NewRouter()
	router.HandleFunc("/token", as.handleToken)
	router.HandleFunc("/introspect", as.handleIntrospect)

	// Mutual DTLS listener against the demo CA (DTLS 1.2, RFC 9202).
	listener, err := net.NewDTLSListener("udp", asAddr, net.NewDTLSServerOptions(
		piondtls.WithCertificates(toTLSCertificate(pki.asCert)),
		piondtls.WithClientCAs(pki.caPool),
		piondtls.WithClientAuth(piondtls.RequireAndVerifyClientCert),
		piondtls.WithExtendedMasterSecret(piondtls.RequireExtendedMasterSecret),
	))
	if err != nil {
		return nil, fmt.Errorf("unable to open AS DTLS listener: %w", err)
	}
	go func() {
		_ = dtls.NewServer(options.WithMux(router)).Serve(listener) // returns on close
	}()
	return as, nil
}

// toTLSCertificate converts a demo leaf to a tls.Certificate for pion.
func toTLSCertificate(c tlsCertificate) tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{c.cert.Raw},
		PrivateKey:  c.key,
	}
}

// handleToken implements RFC 9200 section 5.8.1 (request) and 5.8.2/5.8.3
// (Access Information / error) over CoAP POST /token.
//
//nolint:funlen,gocyclo // linear RFC-ordered handler; each guard is a protocol requirement
func (a *authorizationServer) handleToken(w mux.ResponseWriter, r *mux.Message) {
	ctx := r.Context()

	// Section 5.8.1: POST only.
	if r.Code() != codes.POST {
		writeACEError(w, codes.MethodNotAllowed, ace.ErrInvalidRequest, "POST required")
		return
	}
	// application/ace+cbor content format only.
	cf, cfErr := r.ContentFormat()
	if cfErr != nil || cf != message.MediaType(ace.ContentFormatACECBOR) {
		writeACEError(w, codes.BadRequest, ace.ErrInvalidRequest, "content format must be application/ace+cbor")
		return
	}
	body, err := r.ReadBody()
	if err != nil {
		writeACEError(w, codes.BadRequest, ace.ErrInvalidRequest, "unable to read request body")
		return
	}

	// Decode the ACE token request (extensibility: unknown keys ignored).
	req, err := ace.DecodeTokenRequest(body)
	if err != nil {
		writeACEError(w, codes.BadRequest, ace.ErrInvalidRequest, err.Error())
		return
	}

	// Peer certificate from the (already mutually authenticated) DTLS
	// channel; defense-in-depth, the handshake required it already.
	peerCert, ok := peerCertificate(w)
	if !ok {
		writeACEError(w, codes.Unauthorized, ace.ErrInvalidClient, "no client certificate on the DTLS channel")
		return
	}

	// RFC 8705 tls_client_auth through the presentation-agnostic processor.
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peerCert.Raw})
	pemStr := string(pemCert)
	clientIDStr := req.ClientID
	authRes, err := a.authenticator.Authenticate(ctx, &clientv1.AuthenticateRequest{
		ClientId:      &clientIDStr,
		TlsClientCert: &pemStr,
	})
	if err != nil || authRes.Client == nil {
		writeACEError(w, codes.Unauthorized, ace.ErrInvalidClient, "unable to authenticate client certificate")
		return
	}
	ctx = clientauthentication.Inject(ctx, authRes.Client)

	// Token request with the certificate binding: RFC 8705 section 3.1
	// x5t#S256 confirmation (mirror of applyClientCertificateBinding in
	// the HTTP example).
	scope := req.Scope
	audience := req.Audience
	msg := &flowv1.TokenRequest{
		Issuer:    a.issuer,
		Client:    authRes.Client,
		GrantType: oidc.GrantTypeClientCredentials,
		Grant:     &flowv1.TokenRequest_ClientCredentials{ClientCredentials: &flowv1.GrantClientCredentials{}},
		Scope:     &scope,
		Audience:  &audience,
		TokenConfirmation: &tokenv1.TokenConfirmation{
			X5TS256: sdktoken.X509ThumbprintS256(peerCert),
		},
	}

	// Invoke the presentation-agnostic token service.
	res, err := a.tokens.Token(ctx, msg)
	if err != nil || res.Error != nil {
		code, description := errInvalidRequest, "token request rejected"
		if err != nil {
			description = err.Error()
		}
		if res.Error != nil {
			code, description = res.Error.Error, res.Error.ErrorDescription
		}
		writeACEError(w, coapCodeFor(code), errorAbbrev(code), description)
		return
	}

	at := res.AccessToken
	if at == nil {
		writeACEError(w, codes.BadRequest, ace.ErrInvalidRequest, "no access token issued")
		return
	}

	// Access Information (section 5.8.2): cert-bound PoP token,
	// coap_dtls profile (RFC 9202 section 9 abbreviation 1).
	expiresIn := uint64(0)
	if at.Metadata != nil && at.Metadata.ExpiresAt > uint64(time.Now().Unix()) { //nolint:gosec // unix time is non-negative
		expiresIn = at.Metadata.ExpiresAt - uint64(time.Now().Unix()) //nolint:gosec // unix time is non-negative
	}
	var cnf *ace.Confirmation
	if at.Confirmation != nil && at.Confirmation.X5TS256 != "" {
		// Informational key reference: the authoritative binding is the
		// token itself (resolved via introspection).
		cnf = ace.EncodeCnfKid([]byte(at.Confirmation.X5TS256))
	}
	payload := ace.EncodeTokenResponse([]byte(at.Value), expiresIn, ace.TokenTypePoP, cnf, ace.AceProfileCoapDTLS)
	if err := w.SetResponse(codes.Created, message.MediaType(ace.ContentFormatACECBOR), bytes.NewReader(payload)); err != nil {
		fmt.Printf("as: cannot write token response: %v\n", err)
	}
}

// handleIntrospect implements RFC 9200 section 5.9 (CoAP introspection
// variant, Table 6 payload), POST /introspect. The caller is the RS,
// authenticated with its DTLS certificate (registered RS client).
//
//nolint:funlen,gocyclo // linear RFC-ordered handler; each guard is a protocol requirement
func (a *authorizationServer) handleIntrospect(w mux.ResponseWriter, r *mux.Message) {
	ctx := r.Context()

	if r.Code() != codes.POST {
		writeACEError(w, codes.MethodNotAllowed, ace.ErrInvalidRequest, "POST required")
		return
	}
	cf, cfErr := r.ContentFormat()
	if cfErr != nil || cf != message.MediaType(ace.ContentFormatACECBOR) {
		writeACEError(w, codes.BadRequest, ace.ErrInvalidRequest, "content format must be application/ace+cbor")
		return
	}
	body, err := r.ReadBody()
	if err != nil {
		writeACEError(w, codes.BadRequest, ace.ErrInvalidRequest, "unable to read request body")
		return
	}
	tokenValue, _, err := ace.DecodeIntrospectionRequest(body)
	if err != nil {
		writeACEError(w, codes.BadRequest, ace.ErrInvalidRequest, err.Error())
		return
	}

	// RS authentication: its certificate SAN URI identifies the fixture.
	peerCert, ok := peerCertificate(w)
	if !ok {
		writeACEError(w, codes.Unauthorized, ace.ErrInvalidClient, "no client certificate on the DTLS channel")
		return
	}
	rsClient, err := a.clients.GetByName(ctx, "coap-ace-rs")
	if err != nil || rsClient == nil || !clientauthentication.TLSClientBindingMatches(rsClient, peerCert) {
		writeACEError(w, codes.Unauthorized, ace.ErrInvalidClient, "RS certificate not bound to a registered client")
		return
	}

	res, err := a.tokens.Introspect(ctx, &tokenv1.IntrospectRequest{
		Issuer: a.issuer,
		Client: rsClient,
		Token:  string(tokenValue),
	})
	if err != nil || res.Error != nil {
		code, description := errInvalidRequest, "introspection rejected"
		if err != nil {
			description = err.Error()
		}
		if res.Error != nil {
			code, description = res.Error.Error, res.Error.ErrorDescription
		}
		writeACEError(w, coapCodeFor(code), errorAbbrev(code), description)
		return
	}

	// Inactive / unknown tokens render as active=false with no claims
	// (RFC 9200 section 5.9.2; RFC 7662 section 2.2 no-cause-distinction).
	t := res.Token
	if t == nil || t.Status != tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE {
		if err := w.SetResponse(codes.Content, message.MediaType(ace.ContentFormatACECBOR), bytes.NewReader(ace.EncodeIntrospectionResponse(false, "", "", 0, 0, 0, nil))); err != nil {
			fmt.Printf("as: cannot write inactive introspection response: %v\n", err)
		}
		return
	}

	var cnf *ace.Confirmation
	if t.Confirmation != nil && t.Confirmation.X5TS256 != "" {
		cnf = ace.EncodeCnfKid([]byte(t.Confirmation.X5TS256))
	}
	var scope, clientIDOut string
	var exp, iat, nbf uint64
	if t.Metadata != nil {
		clientIDOut = t.Metadata.ClientId
		scope = t.Metadata.Scope
		exp = t.Metadata.ExpiresAt
		iat = t.Metadata.IssuedAt
		nbf = t.Metadata.NotBefore
	}
	payload := ace.EncodeIntrospectionResponse(true, scope, clientIDOut, exp, iat, nbf, cnf)
	if err := w.SetResponse(codes.Content, message.MediaType(ace.ContentFormatACECBOR), bytes.NewReader(payload)); err != nil {
		fmt.Printf("as: cannot write introspection response: %v\n", err)
	}
}

// ----------------------------------------------------------------------------

// peerCertificate extracts the leaf peer certificate from the DTLS
// connection under a CoAP handler.
func peerCertificate(w mux.ResponseWriter) (*x509.Certificate, bool) {
	dtlsConn, ok := w.Conn().NetConn().(*piondtls.Conn)
	if !ok {
		return nil, false
	}
	state, ok := dtlsConn.ConnectionState()
	if !ok || len(state.PeerCertificates) == 0 {
		return nil, false
	}
	cert, err := x509.ParseCertificate(state.PeerCertificates[0])
	if err != nil {
		return nil, false
	}
	return cert, true
}

// (The SAN-URI binding check itself is shared with the token endpoint:
// clientauthentication.TLSClientBindingMatches, RFC 8705 section 2.1.2.)
