package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/client"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/token/jwt"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/storage/inmemory"
)

// -----------------------------------------------------------------------------
type identity struct {
	Subject  string
	ClientID string
}

func authenticateWithBearer(w http.ResponseWriter, req *http.Request, cli client.Client) (*identity, error) {
	ctx := req.Context()

	// Get token from request
	parts := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	if !strings.EqualFold(parts[0], "bearer") {
		return nil, errors.New("Authorization header must be a 'Bearer' token.")
	}

	// Prepare assertion
	assertion, err := cli.Assertion()
	if err != nil {
		return nil, fmt.Errorf("unable to prepare client authentication assertion: %w", err)
	}

	// Send introspection request to the issuer.
	t, err := cli.Introspect(ctx, assertion, parts[1])
	if err != nil {
		return nil, errors.New("Unable to get a successful token introspection response.")
	}
	switch {
	case t.Status != corev1.TokenStatus_TOKEN_STATUS_ACTIVE:
		return nil, errors.New("Token is inactive.")
	case t.Confirmation != nil:
		return nil, errors.New("Token requires a PoP proof to be used.")
	}

	return &identity{
		Subject:  t.Metadata.Subject,
		ClientID: t.Metadata.ClientId,
	}, nil
}

func authenticateWithDPoP(w http.ResponseWriter, req *http.Request, cli client.Client, dpopVerifier dpop.Verifier) (*identity, error) {
	ctx := req.Context()

	// Get token from request
	parts := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	if !strings.EqualFold(parts[0], "dpop") {
		return nil, errors.New("Authorization header must be a 'DPoP' token.")
	}

	// Check DPoP proof
	dpopProof := req.Header.Get("DPoP")

	// Validate dpop
	expectedJkt, err := dpopVerifier.Verify(ctx, req.Method, dpop.CleanURL(req), dpopProof,
		dpop.WithTokenValue(parts[1]),
	)
	if err != nil {
		return nil, errors.New("Invalid DPoP proof.")
	}

	// Prepare assertion
	assertion, err := cli.Assertion()
	if err != nil {
		return nil, fmt.Errorf("unable to prepare client authentication assertion: %w", err)
	}

	// Send introspection request to the issuer.
	t, err := cli.Introspect(ctx, assertion, parts[1])
	if err != nil {
		return nil, errors.New("Unable to get a successful token introspection response.")
	}
	switch {
	case t.Status != corev1.TokenStatus_TOKEN_STATUS_ACTIVE:
		return nil, errors.New("Token is inactive.")
	case t.Confirmation == nil:
		return nil, errors.New("Request is using a DPoP with a token without PoP.")
	}

	// Compare token confirmation
	if !types.SecureCompareString(expectedJkt, t.Confirmation.Jkt) {
		return nil, errors.New("Invalid token.")
	}

	return &identity{
		Subject:  t.Metadata.Subject,
		ClientID: t.Metadata.ClientId,
	}, nil
}

func Authorizer(next http.Handler, intent string, cli client.Client) http.Handler {
	// Initialize the DPoP verifier.
	dpopVerifier := dpop.DefaultVerifier(inmemory.DPoPProofs(), jwt.EmbeddedKeyVerifier([]string{"ES384"}))

	permissions := map[string]map[string]types.StringArray{
		"timestamp:read": {
			"6779ef20e75817b79602": {
				"", // Allow client itself
			},
			"t8p9duw4n2klximkv3kagaud796ul67g": {
				"",
			},
		},
	}

	can := func(id *identity, intent string) bool {
		// Check permission request
		clients, ok := permissions[intent]
		if !ok {
			return false
		}

		// Check subject permission
		subjects, ok := clients[id.ClientID]
		if !ok {
			return false
		}

		return subjects.Contains(id.Subject)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			id      *identity
			authErr error
		)

		// Check if token is provided.
		authHeader := r.Header.Get("Authorization")
		switch {
		case authHeader == "":
			http.Error(w, "Authorization required.", http.StatusUnauthorized)
			return
		case strings.HasPrefix(strings.ToLower(authHeader), "bearer"):
			id, authErr = authenticateWithBearer(w, r, cli)
		case strings.HasPrefix(strings.ToLower(authHeader), "dpop"):
			id, authErr = authenticateWithDPoP(w, r, cli, dpopVerifier)
		default:
			http.Error(w, "Unsupported authorization method.", http.StatusBadRequest)
			return
		}

		// Authenticate the token
		if authErr != nil {
			log.Printf("auth error: %v", authErr)
			http.Error(w, "Unable to authenticate the request intent.", http.StatusUnauthorized)
			return
		}

		// Authorize the identity for intent
		if !can(id, intent) {
			http.Error(w, "Operation not allowed for this identity.", http.StatusForbidden)
			return
		}

		// Delegate to next handler.
		next.ServeHTTP(w, r)
	})
}

// -----------------------------------------------------------------------------

func ResourceHandler() http.Handler {
	// Create the signing key.
	pub, priv, err := ed25519.GenerateKey(strings.NewReader("deterministic-key-generation-for-testing-purpose-0000"))
	if err != nil {
		panic(err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create the timestamp
		now := time.Now().UTC().Format(time.RFC3339)

		// Create a random nonce
		var nonce [24]byte
		if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
			http.Error(w, "Unable to generate nonce for signature", http.StatusInternalServerError)
			return
		}

		// Prepare protected payload
		protected := []byte("signed-timestamp-protocol-v1")
		protected = append(protected, nonce[:]...)
		protected = append(protected, []byte(now)...)

		// Set response type
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// Prepare response
		if err := json.NewEncoder(w).Encode(map[string]any{
			"@timestamp": now,
			"nonce":      base64.RawURLEncoding.EncodeToString(nonce[:]),
			"proof":      base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, protected)),
			"kid":        base64.RawURLEncoding.EncodeToString(pub),
		}); err != nil {
			http.Error(w, "Unable to serialize response", http.StatusInternalServerError)
			return
		}
	})
}

func main() {
	ctx := context.Background()

	// Create OIDC client instance
	oidcClient, err := client.HTTP(ctx, "http://localhost:8080", &client.Options{
		ClientID: "5stz52n91hr7aw9q1h5hbuvkt2ovevdw",
		JWK:      []byte(`{"kty":"EC","crv":"P-384","alg":"ES384","x":"YvJISWbCgiUhED5jb_N6UEem2jwN4WU2kIgC3KsT1tXS2FB7PSKdFdx76vtUW2e3","y":"XYEHKEfIH8dd2xqZ8oTO8COnOs_OpFs71xvncT3c-3koJYix4Sb9c-drRRRRAqnK","d":"uSBGgPvr8_k_6tFpN46C4S5kjfxfVwW25tT3lcVyUqeNq3TKD65o21LG58X7v88h"}`),
		Scopes:   []string{"openid"},
	})
	if err != nil {
		panic(err)
	}

	// Create router
	http.Handle("/", Authorizer(ResourceHandler(), "timestamp:read", oidcClient))

	log.Fatal(http.ListenAndServe(":8085", nil))
}
