package jwt

import (
	"github.com/square/go-jose/v3"
	"zntr.io/solid/pkg/sdk/jwk"
	"zntr.io/solid/pkg/sdk/token"
)

// AccessTokenSigner represents JWT Access Token signer.
func AccessTokenSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "at+jwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// RefreshTokenSigner represents JWT Refresh Token signer.
func RefreshTokenSigner(alg jose.SignatureAlgorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "rt+jwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}
