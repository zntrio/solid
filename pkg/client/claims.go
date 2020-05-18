package client

// RequestURIResponse contains all request_uri creation related information.
type RequestURIResponse struct {
	RequestURI   string `json:"request_uri"`
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
}

// -----------------------------------------------------------------------------

type privateJWTClaims struct {
	JTI      string `json:"jti"`
	Subject  string `json:"sub"`
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Expires  uint64 `json:"exp"`
	IssuedAt uint64 `json:"iat"`
}

type jsonError struct {
	ErrorCode        string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type jsonRequestURIResponse struct {
	Error *jsonError `json:"inline"`

	RequestURI string `json:"request_uri"`
}
