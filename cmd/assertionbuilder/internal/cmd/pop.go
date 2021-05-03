// Licensed to SolID under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. SolID licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

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
