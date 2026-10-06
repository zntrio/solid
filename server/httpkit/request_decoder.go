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

package httpkit

import (
	"context"
	"fmt"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/jwsreq"
	"zntr.io/solid/sdk/token/jwt"
)

// clientRequestDecoder assembles the JAR request-object decoder for a
// client: the JWT verifier resolves the signing keys from the client's
// registered JWKS, restricted to the AS-supported algorithms. Shared by
// the authorization and PAR endpoints.
func clientRequestDecoder(client *clientv1.Client, issuer string, algorithms []string) jwsreq.AuthorizationDecoder {
	return jwsreq.AuthorizationRequestDecoder(jwt.DefaultVerifier(func(ctx context.Context) (jwk.Set, error) {
		parsed, parseErr := jwk.Parse(client.Jwks)
		if parseErr != nil {
			return nil, fmt.Errorf("unable to decode client JWKS")
		}

		// No error
		return parsed, nil
	}, algorithms), issuer)
}
