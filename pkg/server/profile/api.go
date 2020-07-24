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

package profile

import "zntr.io/solid/pkg/sdk/types"

// Client defines client profile contract.
type Client interface {
	GrantTypesSupported() types.StringArray
	TokenEndpointAuthMethodsSupported() types.StringArray
	ResponseTypesSupported() types.StringArray
	DefaultScopes() types.StringArray
}

// Server defines server profile contract.
type Server interface {
	ApplicationType(name string) (Client, bool)
}
