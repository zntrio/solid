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

package dpop

import (
	"context"
	"time"
)

const (
	// HeaderType defines typ claim value
	HeaderType = "dpop+jwt"
	// ExpirationTreshold defines clock swrew tolerance
	ExpirationTreshold = 15 * time.Second
	// JTICodeLength defines JTI claim string length
	JTICodeLength = 16
)

//go:generate mockgen -destination mock/authentication_processor.gen.go -package mock zntr.io/solid/pkg/sdk/dpop Prover

// Prover describes prover contract
type Prover interface {
	Prove(htm string, htu string) (string, error)
}

//go:generate mockgen -destination mock/authentication_processor.gen.go -package mock zntr.io/solid/pkg/sdk/dpop Verifier

// Verifier describes proof verifier contract.
type Verifier interface {
	Verify(ctx context.Context, htm, htu, proof string) (string, error)
}
