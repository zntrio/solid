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

package jwk

import (
	"context"

	"github.com/square/go-jose/v3"
)

// KeySetProviderFunc defines key set provider contract.
type KeySetProviderFunc func(ctx context.Context) (*jose.JSONWebKeySet, error)

// KeyProviderFunc defines key provider contract.
type KeyProviderFunc func(ctx context.Context) (*jose.JSONWebKey, error)
