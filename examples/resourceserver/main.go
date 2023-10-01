package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
	"zntr.io/solid/client"
	"zntr.io/solid/sdk/types"
)

func ResourceMetadata(issuer string) http.Handler {
	// Prepare metadata
	md := &discoveryv1.ProtectedResourceMetadata{
		Resource:  "http://127.0.0.1:8085",
		ScopesProvided: []string{
			"timestamp:read",
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set response type
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// Prepare response
		if err := json.NewEncoder(w).Encode(md); err != nil {
			http.Error(w, "Unable to serialize response", http.StatusInternalServerError)
			return
		}
	})	
}

func ResourceHandler(issuer string, pub ed25519.PublicKey, priv ed25519.PrivateKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create the timestamp
		now := time.Now().UTC().UnixNano()

		// Create a random nonce
		var nonce [8]byte
		if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
			http.Error(w, "Unable to generate nonce for signature", http.StatusInternalServerError)
			return
		}

		// Encode timestamp as a byte array
		tsRaw := make([]byte, 8)
		binary.BigEndian.PutUint64(tsRaw, uint64(now))

		// Prepare protected payload
		protected := []byte("signed-timestamp-protocol-v1")
		protected = append(protected, issuer...)
		protected = append(protected, nonce[:]...)
		protected = append(protected, tsRaw...)

		// Set response type
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// Prepare response
		if err := json.NewEncoder(w).Encode(map[string]any{
			"@context":  "https://zntr.io/schemas/security/v1",
			"@type":     "SignedTimestamp",
			"issuer":    issuer,
			"timestamp": now,
			"signature": map[string]any{
				"scheme": "ed25519",
				"nonce":  base64.RawURLEncoding.EncodeToString(nonce[:]),
				"proof":  base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, protected)),
				"pub":    base64.RawURLEncoding.EncodeToString(pub),
			},
		}); err != nil {
			http.Error(w, "Unable to serialize response", http.StatusInternalServerError)
			return
		}
	})
}

func main() {
	ctx := context.Background()
	issuer := "http://localhost:8085"

	// Create OIDC client instance
	oidcClient, err := client.HTTP(ctx, "http://localhost:8080", &client.Options{
		ClientID: "5stz52n91hr7aw9q1h5hbuvkt2ovevdw",
		JWK:      []byte(`{"kty":"EC","crv":"P-384","alg":"ES384","x":"YvJISWbCgiUhED5jb_N6UEem2jwN4WU2kIgC3KsT1tXS2FB7PSKdFdx76vtUW2e3","y":"XYEHKEfIH8dd2xqZ8oTO8COnOs_OpFs71xvncT3c-3koJYix4Sb9c-drRRRRAqnK","d":"uSBGgPvr8_k_6tFpN46C4S5kjfxfVwW25tT3lcVyUqeNq3TKD65o21LG58X7v88h"}`),
		Scopes:   []string{"openid"},
	})
	if err != nil {
		panic(err)
	}

	// Create the signing key.
	pub, priv, err := ed25519.GenerateKey(strings.NewReader("deterministic-key-generation-for-testing-purpose-0000"))
	if err != nil {
		panic(err)
	}

	// Create router
	http.Handle("/", Authorizer(ResourceHandler(issuer, pub, priv), "timestamp:read", oidcClient, types.StringArray{"urn:solid:loa:1fa:any"}, 30))
	http.Handle("/.well-known/oauth-protected-resource", ResourceMetadata(issuer))

	log.Fatal(http.ListenAndServe(":8085", nil))
}
