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

package jwt

//go:generate mockgen -destination mock/signer.gen.go -package mock zntr.io/solid/pkg/sdk/jwt Signer

// Signer describe JWT signer contract.
type Signer interface {
	Sign(claims interface{}) (string, error)
}

//go:generate mockgen -destination mock/verifier.gen.go -package mock zntr.io/solid/pkg/sdk/jwt Verifier

// Verifier describes JWT verifier contract.
type Verifier interface {
	Parse(token string) (Token, error)
	Verify(token string) error
}

//go:generate mockgen -destination mock/token.gen.go -package mock zntr.io/solid/pkg/sdk/jwt Token

// Token represents a jwt token contract.
type Token interface {
	Type() (string, error)
	PublicKey() (interface{}, error)
	PublicKeyThumbPrint() (string, error)
	Algorithm() (string, error)
	Claims(publicKey interface{}, claims interface{}) error
}
