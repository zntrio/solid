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
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"github.com/square/go-jose/v3"
	"google.golang.org/protobuf/encoding/protojson"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/pkg/sdk/jwsreq"
	"zntr.io/solid/pkg/sdk/token/jwt"
)

var jwsreqCmd = func() *cobra.Command {
	c := &cobra.Command{
		Use:     "jwsreq",
		Aliases: []string{"ar"},
		Short:   "Generate JWSREQ assertion",
		Run: func(cmd *cobra.Command, _ []string) {
			runJWSReq(cmd.Context())
		},
	}

	return c
}

func runJWSReq(ctx context.Context) {
	g := jwsreq.AuthorizationRequestEncoder(jwt.ClientAssertionSigner(jose.ES384, keyProvider()))

	in, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	var req corev1.AuthorizationRequest
	if err := protojson.Unmarshal(in, &req); err != nil {
		panic(err)
	}

	raw, err := g.Encode(ctx, &req)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", raw)
}
