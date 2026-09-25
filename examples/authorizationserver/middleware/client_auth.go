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

package middleware

import (
	"context"
	"encoding/pem"
	"log"
	"net/http"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/examples/authorizationserver/respond"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/storage"
	"zntr.io/solid/server/storage/inmemory"
)

// ClientAuthentication is a middleware to handle client authentication. The
// spiffeBundles source provides the trust-domain signing keys for the
// SPIFFE client authentication methods (draft-ietf-oauth-spiffe-client-auth-02).
func ClientAuthentication(clients storage.ClientReader, issuer string, supportedAlgorithms []string, spiffeBundles spiffe.BundleSource) Adapter {
	// Prepare client authentication. The audience surface is the AS issuer
	// identifier (draft-ietf-oauth-security-topics-update-03 section 2.1.2.1)
	// plus the exact receiving endpoint, resolved per-request below (section
	// 2.1.2.2).
	clientAuth := clientauthentication.PrivateKeyJWT(clients, inmemory.DPoPProofs(), issuer, supportedAlgorithms)
	clientAttestationAuth := clientauthentication.ClientAttestation(clients, inmemory.DPoPProofs(), issuer, supportedAlgorithms)
	spiffeJWTAuth := clientauthentication.SPIFFEJWT(clients, spiffeBundles, inmemory.DPoPProofs(), issuer, supportedAlgorithms)
	spiffeWITAuth := clientauthentication.SPIFFEWIT(clients, spiffeBundles, inmemory.DPoPProofs(), issuer, supportedAlgorithms)
	spiffeX509Auth := clientauthentication.SPIFFEX509(clients, spiffeBundles)
	tlsClientAuth := clientauthentication.TLSClientAuth(clients)
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				ctx         = r.Context()
				q           = r.URL.Query()
				clientIDRaw = q.Get("client_id")
			)

			if clientIDRaw != "" {
				// Retrieve client details
				client, err := clients.Get(ctx, clientIDRaw)
				if err != nil {
					log.Println("unable to retrieve client:", err)
					respond.WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
					return
				}

				if client.ClientType == clientv1.ClientType_CLIENT_TYPE_PUBLIC {
					// Assign client to context
					ctx = clientauthentication.Inject(ctx, client)
				} else {
					log.Println("missing client authentication")
					respond.WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
					return
				}
			} else {
				if err := r.ParseForm(); err != nil {
					log.Println("unable to parse form:", err)
					respond.WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
					return
				}

				var (
					authMethod    = r.PostFormValue("client_assertion_type")
					assertion     = r.PostFormValue("client_assertion")
					authenticator clientauthentication.AuthenticationProcessor
					// draft-ietf-oauth-spiffe-client-auth-02 section 3.3:
					// WIT-SVID carriage via the attestation headers.
					attestation    = r.Header.Get("OAuth-Client-Attestation")
					attestationPop = r.Header.Get("OAuth-Client-Attestation-PoP")
				)

				// SPIFFE methods with dedicated inputs (draft-ietf-oauth-
				// spiffe-client-auth-02 sections 3.2, 3.3): dispatch on the
				// client_assertion_type form parameter when present, then on
				// the attestation headers, then on a presented TLS client
				// certificate (mutual TLS X.509-SVID).
				clientIDParam := r.PostFormValue("client_id")

				// RFC 8705 section 2: hoist the PEM-encoded client certificate
				// for any mutual-TLS request; both the SPIFFE X.509-SVID and the
				// PKI tls_client_auth method receive it as tls_client_cert.
				tlsClientCertPEM := pemClientCertificate(r)

				authenticator, okAuth := selectAuthenticator(ctx, clients, authMethod, attestation, attestationPop, tlsClientCertPEM, clientIDParam, clientAuth, clientAttestationAuth, spiffeJWTAuth, spiffeWITAuth, spiffeX509Auth, tlsClientAuth)
				if !okAuth {
					respond.WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidRequest().Build())
					return
				}

				// Build the authentication request inputs.
				req := &clientv1.AuthenticateRequest{
					ClientAssertionType: new(authMethod),
					ClientAssertion:     new(assertion),
					ClientId:            new(clientIDParam),
				}

				if tlsClientCertPEM != "" {
					req.TlsClientCert = new(tlsClientCertPEM)
					// draft section 3.2: when the x509 leaf SAN carries the
					// SPIFFE ID and no client_id parameter was given, the
					// middleware resolves it for the client binding.
					if authenticator == spiffeX509Auth && clientIDParam == "" {
						leaf := r.TLS.PeerCertificates[0]
						if spiffeID, ok := spiffe.TrustDomainFromX509SVID(leaf); ok {
							req.ClientId = new(spiffeID)
						}
					}
				}

				// draft section 3.3: WIT-SVID + PoP from the attestation headers.
				if authenticator == spiffeWITAuth {
					req.ClientAttestation = new(attestation)
					req.ClientAttestationPop = new(attestationPop)
				}

				// Process authentication, carrying the receiving endpoint URI
				// for endpoint-exact audience validation
				// (draft-ietf-oauth-security-topics-update-03 section 2.1.2.2).
				receivingEndpoint := issuer + r.URL.Path
				req.Endpoint = &receivingEndpoint
				resAuth, err := authenticator.Authenticate(ctx, req)
				if err != nil {
					log.Println("unable to authenticate client:", err)
					respond.WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
					return
				}

				// Assign client to context
				ctx = clientauthentication.Inject(ctx, resAuth.Client)
			}

			// Delegate to next handler
			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// pemClientCertificate returns the PEM-encoded leaf client certificate
// presented over mutual TLS, or an empty string (RFC 8705 section 2).
func pemClientCertificate(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}

	leaf := r.TLS.PeerCertificates[0]
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leaf.Raw,
	})
	return string(pemCert)
}

// selectAuthenticator resolves the client authentication method from the
// request inputs (SPIFFE draft sections 3.2/3.3, RFC 8705 section 2.1).
func selectAuthenticator(ctx context.Context, clients storage.ClientReader, authMethod, attestation, attestationPop, tlsClientCertPEM, clientIDParam string,
	clientAuth, clientAttestationAuth, spiffeJWTAuth, spiffeWITAuth, spiffeX509Auth, tlsClientAuth clientauthentication.AuthenticationProcessor) (clientauthentication.AuthenticationProcessor, bool) {
	switch {
	case authMethod == oidc.AssertionTypeJWTSPIFFE:
		return spiffeJWTAuth, true
	case authMethod == "" && attestation != "" && attestationPop != "":
		return spiffeWITAuth, true
	case authMethod == "" && tlsClientCertPEM != "":
		// RFC 8705 section 2.1 takes precedence when the resolved
		// client is registered for tls_client_auth; otherwise the
		// certificate is an X.509-SVID candidate (SPIFFE draft
		// section 3.2).
		if clientIDParam != "" {
			if registered, err := clients.Get(ctx, clientIDParam); err == nil &&
				registered.TokenEndpointAuthMethod == oidc.AuthMethodTLSClientAuth {
				return tlsClientAuth, true
			}
		}
		return spiffeX509Auth, true
	case authMethod == oidc.AssertionTypeJWTBearer:
		return clientAuth, true
	case authMethod == oidc.AssertionTypeJWTClientAttestation:
		return clientAttestationAuth, true
	default:
		return nil, false
	}
}
