package cwt

import (
	"go.mozilla.org/cose"

	"zntr.io/solid/pkg/sdk/jwk"
	"zntr.io/solid/pkg/sdk/token"
)

// AccessTokenSigner represents CWT Access Token signer.
func AccessTokenSigner(alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "at+cwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// RefreshTokenSigner represents CWT Refresh Token signer.
func RefreshTokenSigner(alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "rt+cwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// RequestSigner represents CWT Request Token signer.
func RequestSigner(alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "oauth-authz-req+cwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// JARMSigner represents CWT JARM Token signer.
func JARMSigner(alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "jarm+cwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// DPoPSigner represents CWT DPoP Token signer.
func DPoPSigner(alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "dpop+cwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// ClientAssertionSigner represents CWT Client Assertion signer.
func ClientAssertionSigner(alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "client-assertion+cwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// TokenIntrospection represents CWT Token Introspection Assertion signer.
func TokenIntrospection(alg *cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   "token-introspection+cwt",
		alg:         alg,
		keyProvider: keyProvider,
	}
}
