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
