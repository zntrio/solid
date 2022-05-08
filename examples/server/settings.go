package main

import (
	"context"
	"encoding/json"

	"gopkg.in/square/go-jose.v2"
	"zntr.io/solid/sdk/jwk"
)

var jwkPrivateKey = []byte(`{
	"kty": "EC",
	"d": "-3yrGLfHTjuvcpG8gZzwQoz9P6uWgBW6HTmYTb-f6u4HxK05PpTdheKBdQ1nXkV-",
	"use": "sig",
	"crv": "P-384",
	"kid": "123456789",
	"x": "De4LLFSUCTAAU8O7_ew0VkNR03_kTH9SNCFuhbpi8D1JUbhABRLpNygSDLf2waQt",
	"y": "cEXPFElY6-qb-5xsFu875_58D3lKZlcOzD99ulje6CAh4D_rJjYU7quxf82xCAUZ",
	"alg": "ES384"
}`)

func keyProvider() jwk.KeyProviderFunc {
	var privateKey jose.JSONWebKey

	// Decode JWK
	err := json.Unmarshal(jwkPrivateKey, &privateKey)
	if err != nil {
		panic(err)
	}

	return func(_ context.Context) (*jose.JSONWebKey, error) {
		// No error
		return &privateKey, nil
	}
}

func keySetProvider() jwk.KeySetProviderFunc {
	var privateKey jose.JSONWebKey

	// Decode JWK
	err := json.Unmarshal(jwkPrivateKey, &privateKey)
	if err != nil {
		panic(err)
	}

	return func(_ context.Context) (*jose.JSONWebKeySet, error) {
		// No error
		return &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				privateKey.Public(),
			},
		}, nil
	}
}
