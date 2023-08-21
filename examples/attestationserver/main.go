package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type attestationData struct {
	ClientID        string           `json:"clientId"`
	ClientPublicKey *jose.JSONWebKey `json:"clientPublicKey"`
}

func signHandler(priv ed25519.PrivateKey) http.Handler {
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

		// Prepare response signer
		signer, err := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.EdDSA,
			Key:       priv,
		}, &jose.SignerOptions{
			EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				jose.HeaderType: "client-attestation+jwt",
			},
		})
		if err != nil {
			http.Error(w, "Unable to initialize JWT signer", http.StatusInternalServerError)
			return
		}

		// Serialize response
		response, err := jwt.Signed(signer).Claims(map[string]any{
			"iss": "urn:solid:attestation-server",
			"sub": data.ClientID,
			"nbf": now - 1,
			"exp": now + 3600, // Valid for 1h
			"cnf": map[string]any{
				"jwk": data.ClientPublicKey.Public(),
			},
		}).CompactSerialize()

		// Set response type
		w.Header().Set("Content-Type", "application/client-attestation+jwt; charset=utf-8")
		fmt.Fprint(w, response)
	})
}

func publicKeyHandler(pub ed25519.PublicKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prepare protected payload
		payload := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key: pub,
				},
			},
		}

		// Set response type
		w.Header().Set("Content-Type", "application/jwkset+json; charset=utf-8")

		// Prepare response
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			http.Error(w, "Unable to serialize response", http.StatusInternalServerError)
			return
		}
	})
}

func main() {
	// Create the signing key.
	pub, priv, err := ed25519.GenerateKey(strings.NewReader("deterministic-key-generation-for-attestation-signing"))
	if err != nil {
		panic(err)
	}

	// Create router
	http.Handle("/attestations/sign", signHandler(priv))
	http.Handle("/attestations/jwks", publicKeyHandler(pub))

	log.Fatal(http.ListenAndServe(":8087", nil))
}
