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

package oidc

// Grant types -----------------------------------------------------------------

const (
	// GrantTypeAuthorizationCode repesents AuthorizationCode grant type name.
	GrantTypeAuthorizationCode = "authorization_code"
	// GrantTypeClientCredentials repesents ClientCredentials grant type name.
	GrantTypeClientCredentials = "client_credentials"
	// GrantTypeDeviceCode repesents DeviceCode grant type name.
	GrantTypeDeviceCode = "device_code"
	// GrantTypeRefreshToken repesents RefreshToken grant type name.
	GrantTypeRefreshToken = "refresh_token"
)

// Scopes ----------------------------------------------------------------------

const (
	// ScopeOpenID represents OpenID scope name.
	ScopeOpenID = "openid"
	// ScopeOfflineAccess represents offline access scope name.
	ScopeOfflineAccess = "offline_access"
)

// Code Challenge Methods ------------------------------------------------------

const (
	// CodeChallengeMethodSha256 represents sha256 code challenge method name.
	CodeChallengeMethodSha256 = "S256"
)

// Assertion Types -------------------------------------------------------------

const (
	// AssertionTypeJWTBearer repesents JWT Bearer assertion name.
	AssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)
