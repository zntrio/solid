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

package jwsreq

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"fmt"
	"testing"
	"time"

	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"go.uber.org/mock/gomock"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/jwt"
	tokenmock "zntr.io/solid/sdk/token/mock"
)

func Test_jwtEncoder_Encode(t *testing.T) {
	type fields struct {
		signer token.Signer
	}
	type args struct {
		ctx context.Context
		ar  *flowv1.AuthorizationRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		prepare func(*tokenmock.MockSigner)
		want    string
		wantErr bool
	}{
		{
			name:    "nil",
			wantErr: true,
		},
		{
			name: "nil authorization request",
			args: args{
				ar: nil,
			},
			wantErr: true,
		},
		{
			name: "signer error",
			args: args{
				ar: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              new(oidc.PromptConsent),
				},
			},
			prepare: func(signer *tokenmock.MockSigner) {
				signer.EXPECT().Sign(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				ar: &flowv1.AuthorizationRequest{
					Audience:            "mDuGcLjmamjNpLmYZMLIshFcXUDCNDcH",
					ResponseType:        "code",
					Scope:               "openid profile email offline_access",
					ClientId:            "s6BhdRkqt3",
					State:               "oESIiuoybVxAJ5fAKmxxM6s2CnVic6zU",
					Nonce:               "XDwbBH4MokU8BmrZ",
					RedirectUri:         "https://client.example.org/cb",
					CodeChallenge:       "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U",
					CodeChallengeMethod: "S256",
					Prompt:              new(oidc.PromptConsent),
				},
			},
			prepare: func(signer *tokenmock.MockSigner) {
				signer.EXPECT().Sign(gomock.Any(), gomock.Any()).Return("fake-token", nil)
			},
			wantErr: false,
			want:    "fake-token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockSigner := tokenmock.NewMockSigner(ctrl)

			// Prepare mocks
			if tt.prepare != nil {
				tt.prepare(mockSigner)
			}

			enc := AuthorizationRequestEncoder(mockSigner)
			got, err := enc.Encode(tt.args.ctx, tt.args.ar)
			if (err != nil) != tt.wantErr {
				t.Errorf("jwtEncoder.Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("jwtEncoder.Encode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_jwtEncoder_EncodeWithEnvelope asserts the envelope-merged encoder:
// the injected JOSE envelope claims appear in the serialized payload and
// win over payload-derived values; a decode round-trip strips the envelope
// claims and returns the proto-representable request.
func Test_jwtEncoder_EncodeWithEnvelope(t *testing.T) {
	ctx := context.Background()

	// ES256 P-256 fixture key with kid.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixtureKey, err := jwxjwk.Import(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixtureKey.Set(jwxjwk.AlgorithmKey, "ES256"); err != nil {
		t.Fatal(err)
	}
	if err := fixtureKey.Set(jwxjwk.KeyUsageKey, "sig"); err != nil {
		t.Fatal(err)
	}
	if err := jwk.AssignKeyID(fixtureKey); err != nil {
		t.Fatal(err)
	}
	keyProvider := jwk.KeyProviderFunc(func(context.Context) (jwk.Key, error) {
		return fixtureKey, nil
	})
	publicSet := jwk.NewSet()
	if pub, err := fixtureKey.PublicKey(); err != nil {
		t.Fatal(err)
	} else if err := publicSet.AddKey(pub); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	envelope := map[string]any{
		"iss":             "client-1",
		"aud":             "https://as.example.org",
		"exp":             now.Add(5 * time.Minute).Unix(),
		"iat":             now.Unix(),
		"nbf":             now.Unix(),
		"jti":             "jti-1",
		"binding_message": "W4SCT",
	}

	enc := AuthorizationRequestEncoderWithOptions(
		jwt.RequestSigner("ES256", keyProvider),
		envelope,
	)
	encoded, err := enc.Encode(ctx, &flowv1.AuthorizationRequest{
		Scope:     "openid profile",
		LoginHint: new("hello"),
		DpopJkt:   new("jkt-1"),
	})
	if err != nil {
		t.Fatalf("unable to encode with envelope: %v", err)
	}

	// Unverified claim inspection: the envelope claims must ride the
	// payload.
	verifier := jwt.DefaultVerifier(jwk.KeySetProviderFunc(func(context.Context) (jwk.Set, error) {
		return publicSet, nil
	}), []string{"ES256"})
	var claims map[string]any
	if err := verifier.Claims(ctx, encoded, &claims); err != nil {
		t.Fatalf("unable to decode encoded request: %v", err)
	}
	if claims["iss"] != "client-1" || claims["aud"] != "https://as.example.org" || claims["jti"] != "jti-1" {
		t.Errorf("envelope claims missing from payload: iss=%v aud=%v jti=%v", claims["iss"], claims["aud"], claims["jti"])
	}
	if claims["binding_message"] != "W4SCT" {
		t.Errorf("CIBA binding_message missing from payload: %v", claims["binding_message"])
	}
	if claims["scope"] != "openid profile" || claims["login_hint"] != "hello" || claims["dpop_jkt"] != "jkt-1" {
		t.Errorf("payload claims missing: %v", claims)
	}

	// Round-trip: the generic decoder validates and strips the JOSE
	// envelope (aud/exp/nbf/iat/jti/iss), then returns the
	// proto-representable request. Claims without a proto field (the CIBA
	// binding_message) are consumed by the receiving CIBA service from the
	// verified claims map before its proto unmarshal — the generic decoder
	// rejects them, so the round-trip is exercised without the CIBA-
	// specific claim.
	delete(envelope, "binding_message")
	encodedRT, err := enc.Encode(ctx, &flowv1.AuthorizationRequest{
		Scope:     "openid profile",
		LoginHint: new("hello"),
		DpopJkt:   new("jkt-1"),
	})
	if err != nil {
		t.Fatalf("unable to encode for round-trip: %v", err)
	}
	dec := AuthorizationRequestDecoder(verifier, "https://as.example.org")
	ar, err := dec.Decode(ctx, encodedRT)
	if err != nil {
		t.Fatalf("unable to round-trip decode: %v", err)
	}
	if ar.Scope != "openid profile" {
		t.Errorf("scope did not round-trip: %q", ar.Scope)
	}
	if ar.LoginHint == nil || *ar.LoginHint != "hello" {
		t.Errorf("login_hint did not round-trip: %v", ar.LoginHint)
	}
	if ar.DpopJkt == nil || *ar.DpopJkt != "jkt-1" {
		t.Errorf("dpop_jkt did not round-trip: %v", ar.DpopJkt)
	}
}
