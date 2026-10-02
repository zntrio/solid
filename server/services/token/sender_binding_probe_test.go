package token

import (
	"testing"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

// Proves the sender-binding policy gates: a client registered with
// DpopBoundAccessTokens or TlsClientCertificateBoundAccessTokens is
// rejected without a matching token confirmation (RFC 9449 / RFC 8705 §3).
func TestEnforceSenderBinding(t *testing.T) {
	req := func(cnf *tokenv1.TokenConfirmation) *flowv1.TokenRequest {
		return &flowv1.TokenRequest{Issuer: "https://as.example.com", TokenConfirmation: cnf}
	}
	cases := []struct {
		name    string
		client  *clientv1.Client
		confirm *tokenv1.TokenConfirmation
		wantRej bool
	}{
		{"no binding required", &clientv1.Client{}, nil, false},
		{"dpop required, none presented", &clientv1.Client{DpopBoundAccessTokens: true}, nil, true},
		{
			"dpop required, jkt presented", &clientv1.Client{DpopBoundAccessTokens: true},
			&tokenv1.TokenConfirmation{Jkt: "abc"}, false,
		},
		{
			"dpop required, wrong confirmation type", &clientv1.Client{DpopBoundAccessTokens: true},
			&tokenv1.TokenConfirmation{X5TS256: "abc"}, true,
		},
		{"mtls required, none presented", &clientv1.Client{TlsClientCertificateBoundAccessTokens: true}, nil, true},
		{
			"mtls required, x5t presented", &clientv1.Client{TlsClientCertificateBoundAccessTokens: true},
			&tokenv1.TokenConfirmation{X5TS256: "abc"}, false,
		},
		{
			"mtls required, wrong confirmation type", &clientv1.Client{TlsClientCertificateBoundAccessTokens: true},
			&tokenv1.TokenConfirmation{Jkt: "abc"}, true,
		},
		{
			"both required, both presented", &clientv1.Client{DpopBoundAccessTokens: true, TlsClientCertificateBoundAccessTokens: true},
			&tokenv1.TokenConfirmation{Jkt: "a", X5TS256: "b"}, false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := &flowv1.TokenResponse{}
			err := enforceSenderBinding(res, tc.client, req(tc.confirm))
			if tc.wantRej && err == nil {
				t.Error("expected rejection")
			}
			if !tc.wantRej && err != nil {
				t.Errorf("unexpected rejection: %v", err)
			}
			if tc.wantRej && res.Error == nil {
				t.Error("rejection must set a protocol error")
			}
		})
	}
}
