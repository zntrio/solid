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
)

//go:generate mockgen -destination mock/authorization_code.gen.go -package mock zntr.io/solid/sdk/generator AuthorizationCode

// AuthorizationCode describes authorization code generator contract.
type AuthorizationCode interface {
	Validate(ctx context.Context, issuer, in string) error
	Generate(ctx context.Context, issuer string) (string, error)
}

//go:generate mockgen -destination mock/device_user_code.gen.go -package mock zntr.io/solid/sdk/generator DeviceUserCode

// DeviceUserCode describes device user code generator contract.
type DeviceUserCode interface {
	Generate(ctx context.Context, issuer string) (string, error)
}

//go:generate mockgen -destination mock/device_code.gen.go -package mock zntr.io/solid/sdk/generator DeviceCode

// DeviceCode describes device code generator contract.
type DeviceCode interface {
	Validate(ctx context.Context, issuer, in string) error
	Generate(ctx context.Context, issuer string) (string, error)
}

//go:generate mockgen -destination mock/client_id.gen.go -package mock zntr.io/solid/sdk/generator ClientID

// ClientID describes client identified generator contract.
type ClientID interface {
	Generate(ctx context.Context) (string, error)
}

//go:generate mockgen -destination mock/request_uri.gen.go -package mock zntr.io/solid/sdk/generator RequestURI

// RequestURI describes request uri generator contract.
type RequestURI interface {
	Validate(ctx context.Context, issuer, in string) error
	Generate(ctx context.Context, issuer string) (string, error)
}
