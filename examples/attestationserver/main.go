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
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"

	"zntr.io/solid/sdk/jwk"
)

type attestationData struct {
	ClientID        string          `json:"clientId"`
	ClientPublicKey json.RawMessage `json:"clientPublicKey"`
}

func signHandler(priv *mldsa.PrivateKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().Unix()

		// Decode request body
		var data attestationData
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&data); err != nil {
			http.Error(w, "Unable to decode attestation data", http.StatusInternalServerError)
			return
		}

		//
		// Public key should also be under a proof of possession to prevent spoofing.
		//
		// Prepare the public JWK of the signing key for the header
		privJWK, err := jwk.NewMLDSAKey(priv)
		if err != nil {
			http.Error(w, "Unable to import signing key", http.StatusInternalServerError)
			return
		}
		pubJWK, err := privJWK.PublicKey()
		if err != nil {
			http.Error(w, "Unable to derive signing public key", http.StatusInternalServerError)
			return
		}

		// The attested client public key is echoed verbatim in cnf.jwk.

		// Build and sign the attestation
		tok := gojwt.NewWithClaims(jwk.SigningMethodMLDSA65, gojwt.MapClaims{
			"iss": "urn:solid:attestation-server",
			"sub": data.ClientID,
			"nbf": now - 1,
			"exp": now + 3600, // Valid for 1h
			"cnf": map[string]any{
				"jwk": data.ClientPublicKey,
			},
		})
		tok.Header["typ"] = "client-attestation+jwt"
		tok.Header["jwk"] = pubJWK
		response, err := tok.SignedString(priv)
		if err != nil {
			http.Error(w, "Unable to sign attestation", http.StatusInternalServerError)
			return
		}
		// Set response type
		w.Header().Set("Content-Type", "application/client-attestation+jwt; charset=utf-8")
		_, _ = fmt.Fprint(w, response)
	})
}

func publicKeyHandler(pub *mldsa.PublicKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prepare protected payload
		pubJWK, err := jwk.NewMLDSAKeyFromPublic(pub)
		if err != nil {
			http.Error(w, "Unable to import public key", http.StatusInternalServerError)
			return
		}
		set := jwk.NewSet()
		if err := set.AddKey(pubJWK); err != nil {
			http.Error(w, "Unable to build key set", http.StatusInternalServerError)
			return
		}

		// Set response type
		w.Header().Set("Content-Type", "application/jwkset+json; charset=utf-8")

		// Prepare response
		if err := json.NewEncoder(w).Encode(set); err != nil {
			http.Error(w, "Unable to serialize response", http.StatusInternalServerError)
			return
		}
	})
}

func main() {
	// The attestation server signs with a fixed example fixture key so the
	// authorization server (which pins the corresponding public key in its
	// static client registry) verifies attestations across processes. The
	// seed is a published example fixture, not production key material; a
	// real attestation service derives its key from secure hardware.
	seed, err := base64.RawURLEncoding.DecodeString("c29saWQtYXR0ZXN0YXRpb24tc2VydmVyLWZpeHR1cmU")
	if err != nil {
		panic(err)
	}
	priv, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		panic(err)
	}
	pub := priv.PublicKey()

	// Create router
	http.Handle("/attestations/sign", signHandler(priv))
	http.Handle("/attestations/jwks", publicKeyHandler(pub))

	server := &http.Server{
		Addr:              ":8087",
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
