package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dchest/uniuri"

	"github.com/square/go-jose/v3"
	jwt "github.com/square/go-jose/v3/jwt"
)

var (
	clientPrivateKey = []byte(`{"kty": "EC","d": "olYJLJ3aiTyP44YXs0R3g1qChRKnYnk7GDxffQhAgL8","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}`)
)

type privateJWTClaims struct {
	JTI      string `json:"jti"`
	Subject  string `json:"sub"`
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Expires  uint64 `json:"exp"`
	IssuedAt uint64 `json:"iat"`
}

func generateAssertion(claims *privateJWTClaims) string {
	var privateKey jose.JSONWebKey
	// Decode JWK
	err := json.Unmarshal(clientPrivateKey, &privateKey)
	if err != nil {
		panic(err)
	}

	// Prepare a signer
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}

	raw, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		panic(err)
	}

	// Assertion
	return raw
}

func main() {
	fmt.Printf("%s\n", generateAssertion(&privateJWTClaims{
		JTI:      uniuri.NewLen(8),
		Subject:  "6779ef20e75817b79602",
		Issuer:   "6779ef20e75817b79602",
		Audience: "http://localhost:8080",
		Expires:  uint64(time.Now().Add(2 * time.Hour).Unix()),
		IssuedAt: uint64(time.Now().Unix()),
	}))
}
