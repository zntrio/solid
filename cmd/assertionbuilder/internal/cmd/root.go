package cmd

import (
	"context"
	"encoding/json"

	"github.com/spf13/cobra"
	"github.com/square/go-jose/v3"

	"zntr.io/solid/pkg/sdk/jwk"
)

var rootCmd = func() *cobra.Command {
	c := &cobra.Command{
		Use:   "assertionbuilder",
		Short: "Generate OAuth related asseertions / tokens",
	}

	c.AddCommand(clientAssertionCmd())
	c.AddCommand(popCmd())
	c.AddCommand(jwsreqCmd())

	return c
}

// -----------------------------------------------------------------------------

var clientPrivateKey = []byte(`{
	"kid": "6779ef20e75817b79602",
    "kty": "EC",
    "d": "Uwq56PhVB6STB8MvLQWcOsKQlZbBvWFQba8D6Uhb2qDunpzqvoNyFsnAHKS_AkQB",
    "use": "sig",
    "crv": "P-384",
    "x": "m2NDaWfRRGlCkUa4FK949uLtMqitX1lYgi8UCIMtsuR60ux3d00XBlsC6j_YDOTe",
    "y": "6vxuUq3V1aoWi4FQ_h9ZNwUsmcGP8Uuqq_YN5dhP0U8lchdmZJbLF9mPiimo_6p4",
    "alg": "ES384"
}`)

func keyProvider() jwk.KeyProviderFunc {
	var privateKey jose.JSONWebKey

	// Decode JWK
	err := json.Unmarshal(clientPrivateKey, &privateKey)

	return func(_ context.Context) (*jose.JSONWebKey, error) {
		// No error
		return &privateKey, err
	}
}

// -----------------------------------------------------------------------------

// Execute root command.
func Execute() {
	if err := rootCmd().Execute(); err != nil {
		panic(err)
	}
}
