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

package generator

import (
	"context"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
)

//go:generate mockgen -destination mock/authorization_code.gen.go -package mock zntr.io/solid/pkg/generator AuthorizationCode

// AuthorizationCode describes authorization code generator contract.
type AuthorizationCode interface {
	Generate(ctx context.Context) (string, error)
}

//go:generate mockgen -destination mock/token.gen.go -package mock zntr.io/solid/pkg/generator Token

// Token describes accessToken / refreshToken generator contract.
type Token interface {
	Generate(ctx context.Context, jti string, meta *corev1.TokenMeta, cnf *corev1.TokenConfirmation) (string, error)
}

//go:generate mockgen -destination mock/identity.gen.go -package mock zntr.io/solid/pkg/generator Identity

// Identity describes idToken generator contract.
type Identity interface {
	Generate(ctx context.Context) (string, error)
}

//go:generate mockgen -destination mock/device_user_code.gen.go -package mock zntr.io/solid/pkg/generator DeviceUserCode

// DeviceUserCode describes device user code generator contract.
type DeviceUserCode interface {
	Generate(ctx context.Context) (string, error)
}
