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

package clientregistration

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
	"google.golang.org/protobuf/proto"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/server/services"
	"zntr.io/solid/server/storage/inmemory"
	storagemock "zntr.io/solid/server/storage/mock"
)

var testJWKS = []byte(`{"keys": [{"kty": "EC","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}]}`)

var errBoom = fmt.Errorf("storage failure")

// allowAll is an Authorizer that accepts every request.
func allowAll(context.Context, *clientv1.RegisterRequest) bool { return true }

func TestRegister(t *testing.T) {
	tests := []struct {
		name string
		// authorizer gate; nil means disabled.
		authorizer Authorizer
		// request metadata; nil request handled separately.
		metadata *clientv1.ClientMeta
		// writer behavior
		registerErr error
		// expectations
		wantErrCode string
		wantClient  *clientv1.Client // non-nil expects success
	}{
		{
			name:        "nil request",
			authorizer:  allowAll,
			metadata:    nil,
			wantErrCode: "invalid_client_metadata",
		},
		{
			name:        "disabled (nil authorizer)",
			authorizer:  nil,
			metadata:    &clientv1.ClientMeta{},
			wantErrCode: "access_denied",
		},
		{
			name:        "denying authorizer",
			authorizer:  func(context.Context, *clientv1.RegisterRequest) bool { return false },
			metadata:    &clientv1.ClientMeta{},
			wantErrCode: "access_denied",
		},
		{
			name:       "software statement rejected",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				SoftwareStatement: new("eyJhbGciOiJub25lIn0.e30."),
			},
			wantErrCode: "invalid_client_metadata",
		},
		{
			name:       "secret-based auth method rejected",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				TokenEndpointAuthMethod: new(oidc.AuthMethodClientSecretBasic),
				Jwks:                    testJWKS,
			},
			wantErrCode: "invalid_client_metadata",
		},
		{
			name:       "client_secret_jwt rejected",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				TokenEndpointAuthMethod: new(oidc.AuthMethodClientSecretJWT),
				Jwks:                    testJWKS,
			},
			wantErrCode: "invalid_client_metadata",
		},
		{
			name:       "unknown auth method rejected",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				TokenEndpointAuthMethod: new("password"),
				Jwks:                    testJWKS,
			},
			wantErrCode: "invalid_client_metadata",
		},
		{
			name:       "unknown grant type rejected",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				GrantTypes: []string{oidc.GrantTypeSAML2Bearer},
				Jwks:       testJWKS,
			},
			wantErrCode: "invalid_client_metadata",
		},
		{
			name:       "non-code response type rejected",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				GrantTypes:    []string{oidc.GrantTypeAuthorizationCode},
				ResponseTypes: []string{"token"},
				RedirectUris:  []string{"https://client.example.com/cb"},
				Jwks:          testJWKS,
			},
			wantErrCode: "invalid_client_metadata",
		},
		{
			name:       "missing redirect_uris for authorization_code",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				GrantTypes: []string{oidc.GrantTypeAuthorizationCode},
				Jwks:       testJWKS,
			},
			wantErrCode: "invalid_client_metadata",
		},
		{
			name:       "http non-loopback redirect rejected",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				GrantTypes:   []string{oidc.GrantTypeAuthorizationCode},
				RedirectUris: []string{"http://client.example.com/cb"},
				Jwks:         testJWKS,
			},
			wantErrCode: "invalid_client_metadata",
		},
		{
			name:       "redirect with fragment rejected",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				GrantTypes:   []string{oidc.GrantTypeAuthorizationCode},
				RedirectUris: []string{"https://client.example.com/cb#frag"},
				Jwks:         testJWKS,
			},
			wantErrCode: "invalid_client_metadata",
		},
		{
			name:       "missing jwks for private_key_jwt",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
				GrantTypes:              []string{oidc.GrantTypeClientCredentials},
			},
			wantErrCode: "invalid_client_metadata",
		},
		{
			name:       "invalid jwks rejected",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
				GrantTypes:              []string{oidc.GrantTypeClientCredentials},
				Jwks:                    []byte(`{"keys": [{"kty": "oct"}]}`),
			},
			wantErrCode: "invalid_client_metadata",
		},
		{
			name:       "storage failure",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
				GrantTypes:              []string{oidc.GrantTypeClientCredentials},
				Jwks:                    testJWKS,
			},
			registerErr: errBoom,
			wantErrCode: "server_error",
		},
		{
			name:       "success with defaults (confidential, private_key_jwt)",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				RedirectUris: []string{"https://client.example.com/cb"},
				Jwks:         testJWKS,
				ClientName:   new("test client"),
			},
			wantClient: &clientv1.Client{
				ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
				RedirectUris:            []string{"https://client.example.com/cb"},
				ResponseTypes:           []string{oidc.ResponseTypeCode},
				GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
				TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
				Jwks:                    testJWKS,
				ClientName:              "test client",
			},
		},
		{
			name:       "public client via none auth method",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				TokenEndpointAuthMethod: new(oidc.AuthMethodNone),
				GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
				RedirectUris:            []string{"http://localhost:8765/cb"},
			},
			wantClient: &clientv1.Client{
				ClientType:              clientv1.ClientType_CLIENT_TYPE_PUBLIC,
				RedirectUris:            []string{"http://localhost:8765/cb"},
				ResponseTypes:           []string{oidc.ResponseTypeCode},
				GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
				TokenEndpointAuthMethod: oidc.AuthMethodNone,
			},
		},
		{
			name:       "metadata passthrough (bindings, spiffe, flags)",
			authorizer: allowAll,
			metadata: &clientv1.ClientMeta{
				TokenEndpointAuthMethod:               new(oidc.AuthMethodTLSClientAuth),
				GrantTypes:                            []string{oidc.GrantTypeClientCredentials},
				TlsClientAuthSubjectDn:                new("CN=client.example.com"),
				TlsClientCertificateBoundAccessTokens: new(true),
				SpiffeId:                              new("spiffe://example.org/client"),
				SpiffeBundleEndpoint:                  new("https://example.org/bundle"),
				DpopBoundAccessTokens:                 new(false),
			},
			wantClient: &clientv1.Client{
				ClientType:                            clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
				GrantTypes:                            []string{oidc.GrantTypeClientCredentials},
				ResponseTypes:                         []string{oidc.ResponseTypeCode},
				TokenEndpointAuthMethod:               oidc.AuthMethodTLSClientAuth,
				TlsClientAuthSubjectDn:                "CN=client.example.com",
				TlsClientCertificateBoundAccessTokens: true,
				SpiffeId:                              "spiffe://example.org/client",
				SpiffeBundleEndpoint:                  "https://example.org/bundle",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			ctrl := gomock.NewController(t)
			clients := storagemock.NewMockClient(ctrl)
			tokens := storagemock.NewMockToken(ctrl)
			expectRegister := tt.wantClient != nil || tt.registerErr != nil
			if expectRegister {
				clients.EXPECT().Register(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, c *clientv1.Client) (string, error) {
						if tt.registerErr != nil {
							return "", tt.registerErr
						}
						c.ClientId = "generated-id"
						return c.ClientId, nil
					}).Times(1)
			}
			if tt.wantClient != nil && tt.registerErr == nil {
				stored := proto.Clone(tt.wantClient).(*clientv1.Client)
				stored.ClientId = "generated-id"
				tt.wantClient = stored
				// The registration access token is set on the client
				// BEFORE the single Register write.
			}

			svc := New(clients, tokens, tt.authorizer)

			var req *clientv1.RegisterRequest
			if tt.name != "nil request" {
				req = &clientv1.RegisterRequest{Metadata: tt.metadata}
			} else {
				req = nil
			}

			res, err := svc.Register(context.Background(), req)

			if tt.wantErrCode != "" {
				r.Error(err)
				r.NotNil(res)
				r.Equal(tt.wantErrCode, res.GetError().GetError())
				r.Nil(res.GetClient())
				return
			}
			r.NoError(err)
			r.NotNil(res)
			r.Nil(res.GetError())
			r.Equal("generated-id", res.GetClient().GetClientId())
			// No client secret is ever issued.
			r.Empty(res.GetClient().GetClientSecret())
			r.Equal(tt.wantClient.ClientType, res.GetClient().GetClientType())
			r.Equal(tt.wantClient.TokenEndpointAuthMethod, res.GetClient().GetTokenEndpointAuthMethod())
			r.Equal(tt.wantClient.GrantTypes, res.GetClient().GetGrantTypes())
			r.Equal(tt.wantClient.ResponseTypes, res.GetClient().GetResponseTypes())
			r.Equal(tt.wantClient.RedirectUris, res.GetClient().GetRedirectUris())
			r.Equal(tt.wantClient.TlsClientAuthSubjectDn, res.GetClient().GetTlsClientAuthSubjectDn())
			r.Equal(tt.wantClient.SpiffeId, res.GetClient().GetSpiffeId())
			r.Equal(tt.wantClient.SpiffeBundleEndpoint, res.GetClient().GetSpiffeBundleEndpoint())
			r.Equal(tt.wantClient.TlsClientCertificateBoundAccessTokens, res.GetClient().GetTlsClientCertificateBoundAccessTokens())
			// RFC 7592 section 3: a registration access token is issued.
			r.NotEmpty(res.GetRegistrationAccessToken())
			// The bearer token never rides the Client payload.
			r.Empty(res.GetClient().GetRegistrationAccessToken())
		})
	}
}

// registerForManagement registers a client through the real service and
// returns the stored client alongside its registration access token.
func registerForManagement(t *testing.T, svc services.ClientRegistration) (*clientv1.Client, string) {
	t.Helper()

	res, err := svc.Register(context.Background(), &clientv1.RegisterRequest{
		Metadata: &clientv1.ClientMeta{
			TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
			GrantTypes:              []string{oidc.GrantTypeClientCredentials},
			Jwks:                    testJWKS,
		},
	})
	require.NoError(t, err)
	require.Nil(t, res.GetError())
	require.NotEmpty(t, res.GetRegistrationAccessToken())
	require.Empty(t, res.GetClient().GetRegistrationAccessToken())

	return res.GetClient(), res.GetRegistrationAccessToken()
}

func TestRead(t *testing.T) {
	ctx := context.Background()

	t.Run("valid token returns current metadata", func(t *testing.T) {
		r := require.New(t)

		clients := inmemory.Clients()
		svc := New(clients, inmemory.Tokens([]byte("key")), allowAll)

		registered, token := registerForManagement(t, svc)

		res, err := svc.Read(ctx, &clientv1.ReadRequest{
			RegistrationAccessToken: &token,
			ClientId:                &registered.ClientId,
		})
		r.NoError(err)
		r.Nil(res.GetError())
		r.Equal(registered.GetClientId(), res.GetClient().GetClientId())
		// The bearer token is a server-side record only.
		r.Empty(res.GetClient().GetRegistrationAccessToken())
	})

	t.Run("nil request is invalid_request", func(t *testing.T) {
		r := require.New(t)

		svc := New(inmemory.Clients(), inmemory.Tokens([]byte("key")), allowAll)

		res, err := svc.Read(ctx, nil)
		r.Error(err)
		r.NotNil(res)
		r.Equal("invalid_request", res.GetError().GetError())
	})

	t.Run("unknown client is invalid_token", func(t *testing.T) {
		r := require.New(t)

		svc := New(inmemory.Clients(), inmemory.Tokens([]byte("key")), allowAll)

		res, err := svc.Read(ctx, &clientv1.ReadRequest{})
		r.Error(err)
		r.NotNil(res)
		r.Equal("invalid_token", res.GetError().GetError())
	})

	t.Run("wrong token revokes the stored token", func(t *testing.T) {
		r := require.New(t)

		clients := inmemory.Clients()
		svc := New(clients, inmemory.Tokens([]byte("key")), allowAll)

		registered, token := registerForManagement(t, svc)

		wrong := "wrong-token"
		res, err := svc.Read(ctx, &clientv1.ReadRequest{
			RegistrationAccessToken: &wrong,
			ClientId:                &registered.ClientId,
		})
		r.Error(err)
		r.Equal("invalid_token", res.GetError().GetError())

		// The legitimate token no longer authenticates.
		res2, err := svc.Read(ctx, &clientv1.ReadRequest{
			RegistrationAccessToken: &token,
			ClientId:                &registered.ClientId,
		})
		r.Error(err)
		r.Equal("invalid_token", res2.GetError().GetError())
	})
}

func TestUpdate(t *testing.T) {
	ctx := context.Background()

	t.Run("full replacement keeps client_id and token", func(t *testing.T) {
		r := require.New(t)

		clients := inmemory.Clients()
		svc := New(clients, inmemory.Tokens([]byte("key")), allowAll)

		registered, token := registerForManagement(t, svc)

		v2 := "renamed"
		res, err := svc.Update(ctx, &clientv1.UpdateRequest{
			RegistrationAccessToken: &token,
			ClientId:                &registered.ClientId,
			Metadata: &clientv1.ClientMeta{
				TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
				GrantTypes:              []string{oidc.GrantTypeClientCredentials},
				Jwks:                    testJWKS,
				ClientName:              &v2,
			},
		})
		r.NoError(err)
		r.Nil(res.GetError())
		r.Equal(registered.GetClientId(), res.GetClient().GetClientId())
		r.Equal(v2, res.GetClient().GetClientName())
		r.Empty(res.GetClient().GetRegistrationAccessToken())

		// The same registration token still authenticates after update.
		readRes, err := svc.Read(ctx, &clientv1.ReadRequest{
			RegistrationAccessToken: &token,
			ClientId:                &registered.ClientId,
		})
		r.NoError(err)
		r.Nil(readRes.GetError())
		r.Equal(v2, readRes.GetClient().GetClientName())
	})

	t.Run("nil request is invalid_client_metadata", func(t *testing.T) {
		r := require.New(t)

		svc := New(inmemory.Clients(), inmemory.Tokens([]byte("key")), allowAll)

		res, err := svc.Update(ctx, nil)
		r.Error(err)
		r.NotNil(res)
		r.Equal("invalid_client_metadata", res.GetError().GetError())
	})

	t.Run("software statement is invalid_client_metadata", func(t *testing.T) {
		r := require.New(t)

		svc := New(inmemory.Clients(), inmemory.Tokens([]byte("key")), allowAll)

		registered, token := registerForManagement(t, svc)

		res, err := svc.Update(ctx, &clientv1.UpdateRequest{
			RegistrationAccessToken: &token,
			ClientId:                &registered.ClientId,
			Metadata: &clientv1.ClientMeta{
				TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
				GrantTypes:              []string{oidc.GrantTypeClientCredentials},
				Jwks:                    testJWKS,
				SoftwareStatement:       new("x"),
			},
		})
		r.Error(err)
		r.Equal("invalid_client_metadata", res.GetError().GetError())
	})

	t.Run("replace-not-augment drops omitted redirect uris", func(t *testing.T) {
		r := require.New(t)

		svc := New(inmemory.Clients(), inmemory.Tokens([]byte("key")), allowAll)

		registered, token := registerForManagement(t, svc)
		uri := "https://client.example.org/cb"
		res, err := svc.Update(ctx, &clientv1.UpdateRequest{
			RegistrationAccessToken: &token,
			ClientId:                &registered.ClientId,
			Metadata: &clientv1.ClientMeta{
				TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
				GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
				RedirectUris:            []string{uri},
				Jwks:                    testJWKS,
			},
		})
		r.NoError(err)

		// Replacement without redirect_uris while requesting the
		// authorization code grant is rejected: the update is a full
		// replacement, not an augmentation.
		res, err = svc.Update(ctx, &clientv1.UpdateRequest{
			RegistrationAccessToken: &token,
			ClientId:                &registered.ClientId,
			Metadata: &clientv1.ClientMeta{
				TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
				GrantTypes:              []string{oidc.GrantTypeAuthorizationCode},
				Jwks:                    testJWKS,
			},
		})
		r.Error(err)
		r.Equal("invalid_client_metadata", res.GetError().GetError())
	})

	t.Run("invalid auth method is invalid_client_metadata", func(t *testing.T) {
		r := require.New(t)

		svc := New(inmemory.Clients(), inmemory.Tokens([]byte("key")), allowAll)

		registered, token := registerForManagement(t, svc)

		bad := "client_secret_basic"
		res, err := svc.Update(ctx, &clientv1.UpdateRequest{
			RegistrationAccessToken: &token,
			ClientId:                &registered.ClientId,
			Metadata: &clientv1.ClientMeta{
				TokenEndpointAuthMethod: &bad,
				GrantTypes:              []string{oidc.GrantTypeClientCredentials},
				Jwks:                    testJWKS,
			},
		})
		r.Error(err)
		r.Equal("invalid_client_metadata", res.GetError().GetError())
	})
}

func TestDelete(t *testing.T) {
	ctx := context.Background()

	t.Run("happy path removes the client and revokes tokens", func(t *testing.T) {
		r := require.New(t)

		ctrl := gomock.NewController(t)
		clients := inmemory.Clients()
		tokens := storagemock.NewMockToken(ctrl)

		svc := New(clients, tokens, allowAll)

		// Seed the client through the real registration path so the
		// registration access token matches the stored record.
		regRes, err := svc.Register(ctx, &clientv1.RegisterRequest{
			Metadata: &clientv1.ClientMeta{
				TokenEndpointAuthMethod: new(oidc.AuthMethodPrivateKeyJWT),
				GrantTypes:              []string{oidc.GrantTypeClientCredentials},
				Jwks:                    testJWKS,
			},
		})
		r.NoError(err)
		r.Nil(regRes.GetError())
		clientID := regRes.GetClient().GetClientId()
		token := regRes.GetRegistrationAccessToken()

		// Tokens issued to the client must be revoked at deprovision.
		tokens.EXPECT().GetByClientID(gomock.Any(), clientID).Return([]*tokenv1.Token{
			{TokenId: "tok-1", Status: tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE, Metadata: &tokenv1.TokenMeta{ClientId: clientID}},
			{TokenId: "tok-2", Status: tokenv1.TokenStatus_TOKEN_STATUS_ACTIVE, Metadata: &tokenv1.TokenMeta{ClientId: clientID}},
		})
		tokens.EXPECT().Revoke(gomock.Any(), gomock.Any(), "tok-1").Return(nil)
		tokens.EXPECT().Revoke(gomock.Any(), gomock.Any(), "tok-2").Return(nil)

		res, err := svc.Delete(ctx, &clientv1.DeleteRequest{
			RegistrationAccessToken: &token,
			ClientId:                &clientID,
		})
		r.NoError(err)
		r.NotNil(res)
		r.Nil(res.GetError())

		// The client is gone.
		readRes, err := svc.Read(ctx, &clientv1.ReadRequest{
			RegistrationAccessToken: &token,
			ClientId:                &clientID,
		})
		r.Error(err)
		r.Equal("invalid_token", readRes.GetError().GetError())
	})

	t.Run("nil request is invalid_request", func(t *testing.T) {
		r := require.New(t)

		svc := New(inmemory.Clients(), inmemory.Tokens([]byte("key")), allowAll)

		res, err := svc.Delete(ctx, nil)
		r.Error(err)
		r.NotNil(res)
		r.Equal("invalid_request", res.GetError().GetError())
	})

	t.Run("unknown client is invalid_token", func(t *testing.T) {
		r := require.New(t)

		ctrl := gomock.NewController(t)
		tokens := storagemock.NewMockToken(ctrl)

		svc := New(inmemory.Clients(), tokens, allowAll)

		token := "some-token"
		res, err := svc.Delete(ctx, &clientv1.DeleteRequest{
			RegistrationAccessToken: &token,
			ClientId:                new("ghost"),
		})
		r.Error(err)
		r.Equal("invalid_token", res.GetError().GetError())
	})
}
