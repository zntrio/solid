package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

const (
	codeVerifierLen = 96
)

// CodeVerifier genrates and returns code_verifier and code_challenge.
func CodeVerifier() (string, string, error) {
	// Generate random string
	random := make([]byte, codeVerifierLen)
	if _, err := rand.Read(random); err != nil {
		return "", "", err
	}

	// Encode verifier
	verifier := base64.RawURLEncoding.EncodeToString(random)

	// Compute and encode challenge
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// No error
	return verifier, challenge, nil
}
