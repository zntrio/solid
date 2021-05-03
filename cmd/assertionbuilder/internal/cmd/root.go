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
	"encoding/json"

	"github.com/spf13/cobra"
	"gopkg.in/square/go-jose.v2"

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
