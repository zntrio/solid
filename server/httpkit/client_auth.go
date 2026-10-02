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

package httpkit

import (
	"encoding/pem"
	"log"
	"net/http"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/spiffe"
	"zntr.io/solid/server/clientauthentication"
	"zntr.io/solid/server/profile"
	"zntr.io/solid/server/storage"
)

// ClientAuthentication is a middleware to handle client authentication. The
// spiffeBundles source provides the trust-domain signing keys for the
// SPIFFE client authentication methods (draft-ietf-oauth-spiffe-client-auth-02).
// dpopProofs is the shared DPoP proof (jti) store used by the proof-of-
// possession client authentication processors.
//
//nolint:gocyclo // linear presentation-layer dispatch; each branch selects one authentication processor
func ClientAuthentication(clients storage.ClientReader, issuer string, supportedAlgorithms []string, spiffeBundles spiffe.BundleSource, dpopProofs storage.DPoP, profiles profile.Server) Adapter {
	// Prepare the client authentication processors, shared with the other
	// presentation layers (gRPC backend). The audience surface is the AS
	// issuer identifier (draft-ietf-oauth-security-topics-update-03 section
	// 2.1.2.1) plus the exact receiving endpoint, resolved per-request
	// below (section 2.1.2.2).
	procs := clientauthentication.NewProcessorSet(clients, issuer, supportedAlgorithms, spiffeBundles, dpopProofs)
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
					WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
					return
				}

				if client.ClientType == clientv1.ClientType_CLIENT_TYPE_PUBLIC {
					// Assign client to context
					ctx = clientauthentication.Inject(ctx, client)
				} else {
					log.Println("missing client authentication")
					WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
					return
				}
			} else {
				if err := r.ParseForm(); err != nil {
					log.Println("unable to parse form:", err)
					WithError(w, r, http.StatusBadRequest, rfcerrors.InvalidRequest().Build())
					return
				}

				var (
					authMethod = r.PostFormValue("client_assertion_type")
					assertion  = r.PostFormValue("client_assertion")
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

				authenticator, authMethodID, okAuth := procs.Select(ctx, clients, authMethod, attestation, attestationPop, tlsClientCertPEM, clientIDParam)
				if !okAuth {
					WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidRequest().Build())
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
					if authenticator == procs.SPIFFEX509 && clientIDParam == "" {
						leaf := r.TLS.PeerCertificates[0]
						if spiffeID, ok := spiffe.TrustDomainFromX509SVID(leaf); ok {
							req.ClientId = new(spiffeID)
						}
					}
				}

				// draft-ietf-oauth-spiffe-client-auth-02 section 3.3 and
				// draft-ietf-oauth-attestation-based-client-auth-11 sections
				// 4/5.1: both header-transport mechanisms ride the
				// OAuth-Client-Attestation header pair.
				if authenticator == procs.SPIFFEWIT || authenticator == procs.ClientAttestation {
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
					status := http.StatusUnauthorized
					e := rfcerrors.InvalidClient().Build()
					if resAuth != nil && resAuth.GetError() != nil {
						e = resAuth.GetError()
						if e.GetError() == "use_fresh_attestation" {
							// draft-ietf-oauth-attestation-based-client-auth-11
							// section 7.4 / RFC 6749 section 5.2: freshness
							// errors are request errors, not 401 challenges.
							status = http.StatusBadRequest
						}
					}
					WithError(w, r, status, e)
					return
				}

				// Enforce the application-type profile, when the resolved
				// client carries a known application type: the resolved
				// authentication method must be part of the profile's
				// token-endpoint auth methods.
				if prof, okProfile := profiles.ApplicationType(resAuth.Client.ApplicationType); okProfile {
					if !prof.TokenEndpointAuthMethodsSupported().Contains(authMethodID) {
						WithError(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient().Build())
						return
					}
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

	// Encode as PEM
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: r.TLS.PeerCertificates[0].Raw,
	})

	return string(pemCert)
}
