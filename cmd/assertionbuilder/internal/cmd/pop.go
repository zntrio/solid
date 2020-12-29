package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/square/go-jose/v3"

	"zntr.io/solid/pkg/sdk/dpop"
	"zntr.io/solid/pkg/sdk/token/jwt"
)

type popParams struct {
	htm string
	htu string
}

var popCmd = func() *cobra.Command {
	params := &popParams{}

	c := &cobra.Command{
		Use:     "pop",
		Short:   "Generate proof-of-possession assertion",
		Aliases: []string{"dpop"},
		Run: func(cmd *cobra.Command, _ []string) {
			runPop(cmd.Context(), params)
		},
	}

	c.Flags().StringVar(&params.htm, "htm", "GET", "HTTP Method")
	c.Flags().StringVar(&params.htu, "htu", "", "HTTP URL")

	return c
}

func runPop(ctx context.Context, params *popParams) {
	g := dpop.DefaultProver(jwt.ClientAssertionSigner(jose.ES384, keyProvider()))

	raw, err := g.Prove(params.htm, params.htu)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", raw)
}
