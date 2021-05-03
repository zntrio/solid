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
	"time"

	"github.com/dchest/uniuri"
	"github.com/spf13/cobra"
	"gopkg.in/square/go-jose.v2"

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

	raw, err := g.Generate(ctx, &corev1.Token{
		TokenId: uniuri.NewLen(16),
		Metadata: &corev1.TokenMeta{
			Issuer:    p.issuer,
			Subject:   p.subject,
			Audience:  p.audience,
			IssuedAt:  uint64(time.Now().Unix()),
			ExpiresAt: uint64(time.Now().Add(2 * time.Hour).Unix()),
		},
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", raw)
}
