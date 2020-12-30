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
	// GrantTypeAuthorizationCode represents AuthorizationCode grant type name.
	GrantTypeAuthorizationCode = "authorization_code"
	// GrantTypeClientCredentials represents ClientCredentials grant type name.
	GrantTypeClientCredentials = "client_credentials"
	// GrantTypeDeviceCode represents DeviceCode grant type name.
	GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	// GrantTypeRefreshToken represents RefreshToken grant type name.
	GrantTypeRefreshToken = "refresh_token"
	// GrantTypeJWTBearer represents JWT Bearer Token grant type name.
	GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	// GrantTypeSAML2Bearer represents SAML 2 Bearer token grant type.
	GrantTypeSAML2Bearer = "urn:ietf:params:oauth:grant-type:saml2-bearer"
	// GrantTypeTokenExchange represent token exchange flow (RFC8693)
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
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
	// AssertionTypePasetoBearer repesents PASETO Bearer assertion name.
	AssertionTypePasetoBearer = "urn:solid:params:oauth:client-assertion-type:paseto-bearer"
)

// Response Types --------------------------------------------------------------

const (
	// ResponseTypeCode represents the authorization code response type defined
	// in OAuth 2.0
	ResponseTypeCode = "code"
	// ResponseTypeToken represents the implicit response type defined in OAuth 2.0
	ResponseTypeToken = "token"
)

// Response Modes --------------------------------------------------------------

const (
	// ResponseModeJWT represents JARM encoded response.
	ResponseModeJWT = "jwt"
	// ResponseModeQueryJWT represents JARM encoded response as query parameter.
	ResponseModeQueryJWT = "query.jwt"
	// ResponseModeFragmentJWT represents JARM encoded response as fragment.
	ResponseModeFragmentJWT = "fragment.jwt"
	// ResponseModeFormPOSTJWT represents JARM encoded response as form post.
	ResponseModeFormPOSTJWT = "form_post.jwt"
)

// Authentication Methods ------------------------------------------------------

const (
	// AuthMethodNone : The client is a public client as defined in OAuth 2.0
	AuthMethodNone = "none"
	// AuthMethodClientSecretPost : The client uses the HTTP POST parameters as
	// defined in OAuth 2.0
	AuthMethodClientSecretPost = "client_secret_post"
	// AuthMethodClientSecretBasic : The client uses HTTP Basic as defined in
	// OAuth 2.0
	AuthMethodClientSecretBasic = "client_secret_basic"
	// AuthMethodPrivateKeyJWT : The client uses JWT assertion.
	AuthMethodPrivateKeyJWT = "private_key_jwt"
)

// Application Type ------------------------------------------------------------

const (
	// ApplicationTypeServerSideWeb is a web application with authorization logic on the server side.
	ApplicationTypeServerSideWeb = "web"
	// ApplicationTypeClientSideWeb is a rich client web application with all authorization logic in browser.
	ApplicationTypeClientSideWeb = "browser"
	// ApplicationTypeNative is a desktop or a mobile application able to request authorization token non-interactively.
	ApplicationTypeNative = "native"
	// ApplicationTypeService is a script that needs to access resources on behalf of itself.
	ApplicationTypeService = "service"
	// ApplicationTypeDevice is is designed for devices that either do not have access to a browser or have limited input capabilities.
	ApplicationTypeDevice = "device"
)

// Subject Type ----------------------------------------------------------------
// https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes

const (
	// SubjectTypePublic defines subject as public data. This provides the same sub (subject) value to all Clients.
	// It is the default if the provider has no subject_types_supported element in its discovery document.
	SubjectTypePublic = "public"
	// SubjectTypePairwise defines subject masquerade strategy. This provides a different sub value to each Client,
	// so as not to enable Clients to correlate the End-User's activities without permission.
	SubjectTypePairwise = "pairwise"
)

// Token Type ------------------------------------------------------------------
// https://tools.ietf.org/html/rfc8693#section-3

const (
	// TokenExchangeAccessTokenType indicates that the token is an OAuth 2.0 access token issued by
	// the given authorization server.
	TokenExchangeAccessTokenType = "urn:ietf:params:oauth:token-type:access_token"
	// TokenExchangeRefreshTokenType indicates that the token is an OAuth 2.0 refresh token issued by
	// the given authorization server.
	TokenExchangeRefreshTokenType = "urn:ietf:params:oauth:token-type:refresh_token"
	// TokenExchangeIDTokenType indicates that the token is an ID Token as defined in Section 2 of
	// [OpenID.Core].
	TokenExchangeIDTokenType = "urn:ietf:params:oauth:token-type:id_token"
	// TokenExchangeSAML1Type indicates that the token is a base64url-encoded SAML 1.1
	// [OASIS.saml-core-1.1] assertion.
	TokenExchangeSAML1Type = "urn:ietf:params:oauth:token-type:saml1"
	// TokenExchangeSAML2Type indicates that the token is a base64url-encoded SAML 2.0
	// [OASIS.saml-core-2.0-os] assertion.
	TokenExchangeSAML2Type = "urn:ietf:params:oauth:token-type:saml2"
	// TokenExchangeJWTType indicates that the token is a JWT.
	TokenExchangeJWTType = "urn:ietf:params:oauth:token-type:jwt"
)
