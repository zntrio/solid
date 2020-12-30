package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/dchest/uniuri"
	"github.com/spf13/cobra"
	"github.com/square/go-jose/v3"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/token"
	"zntr.io/solid/pkg/sdk/token/jwt"
)

type clientAssertionParams struct {
	issuer   string
	subject  string
	audience string
}

var clientAssertionCmd = func() *cobra.Command {
	params := &clientAssertionParams{}

	c := &cobra.Command{
		Use:     "client-assertion",
		Short:   "Generate client assertion",
		Aliases: []string{"ca"},
		Run: func(cmd *cobra.Command, _ []string) {
			runClientAssertion(cmd.Context(), params)
		},
	}

	c.Flags().StringVar(&params.issuer, "issuer", "6779ef20e75817b79602", "Set iss value")
	c.Flags().StringVar(&params.subject, "subject", "6779ef20e75817b79602", "Set sub value")
	c.Flags().StringVar(&params.audience, "audience", "http://127.0.0.1:8080", "Set aud value")

	return c
}

func runClientAssertion(ctx context.Context, p *clientAssertionParams) {
	g := token.ClientAssertion(jwt.ClientAssertionSigner(jose.ES384, keyProvider()))

	raw, err := g.Generate(ctx, uniuri.NewLen(16), &corev1.TokenMeta{
		Issuer:    p.issuer,
		Subject:   p.subject,
		Audience:  p.audience,
		IssuedAt:  uint64(time.Now().Unix()),
		ExpiresAt: uint64(time.Now().Add(2 * time.Hour).Unix()),
	}, nil)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", raw)
}
