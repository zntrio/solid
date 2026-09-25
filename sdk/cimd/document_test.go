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

package cimd

import (
	"encoding/json"
	"strings"
	"testing"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
)

// validES256PublicJWKS is a public-only EC JWK Set fixture.
const validES256PublicJWKS = `{"keys":[{"kty":"EC","crv":"P-256","kid":"cimd-1","use":"sig","x":"usWxHK2PmwdRMx5tCYESucbsKLUeYS2tK5AFpfMz1sc","y":"AYexF3Xl0Lo0Ol7BsaNvfW4H9OpNQ0JC6T6i5jX6CqA"}]}`

func TestDecodeDocument(t *testing.T) {
	raw := `{
		"client_id": "https://client.example.org/cimd.json",
		"token_endpoint_auth_method": "private_key_jwt",
		"grant_types": ["client_credentials"],
		"redirect_uris": ["https://client.example.org/cb"],
		"jwks": ` + validES256PublicJWKS + `,
		"client_name": "Example Client",
		"scope": "read write",
		"contacts": ["admin@example.org"],
		"software_id": "dev-software",
		"software_version": "1.0.0"
	}`
	doc, err := DecodeDocument([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.ClientID != "https://client.example.org/cimd.json" {
		t.Errorf("client_id = %q", doc.ClientID)
	}
	if doc.TokenEndpointAuthMethod != oidc.AuthMethodPrivateKeyJWT {
		t.Errorf("token_endpoint_auth_method = %q", doc.TokenEndpointAuthMethod)
	}
	if len(doc.GrantTypes) != 1 || doc.GrantTypes[0] != "client_credentials" {
		t.Errorf("grant_types = %v", doc.GrantTypes)
	}
	if doc.SoftwareID != "dev-software" {
		t.Errorf("software_id = %q", doc.SoftwareID)
	}
	if string(doc.Jwks) != validES256PublicJWKS {
		t.Errorf("jwks = %q", doc.Jwks)
	}
}

func TestToClient(t *testing.T) {
	newDoc := func(mutate func(*Document)) *Document {
		d := &Document{
			ClientID:                "https://client.example.org/cimd.json",
			TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
			GrantTypes:              []string{"client_credentials"},
			RedirectUris:            []string{"https://client.example.org/cb"},
			Jwks:                    json.RawMessage(validES256PublicJWKS),
		}
		mutate(d)
		return d
	}

	t.Run("ValidConfidential", func(t *testing.T) {
		c, err := newDoc(func(*Document) {}).ToClient()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ClientId != "https://client.example.org/cimd.json" {
			t.Errorf("client_id = %q", c.ClientId)
		}
		if c.TokenEndpointAuthMethod != oidc.AuthMethodPrivateKeyJWT {
			t.Errorf("token_endpoint_auth_method = %q", c.TokenEndpointAuthMethod)
		}
		if c.ClientType != clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL {
			t.Errorf("client_type = %v", c.ClientType)
		}
		if len(c.Jwks) == 0 {
			t.Error("jwks is empty")
		}
		if len(c.RedirectUris) != 1 || c.RedirectUris[0] != "https://client.example.org/cb" {
			t.Errorf("redirect_uris = %v", c.RedirectUris)
		}
	})

	t.Run("PublicWithoutAuthMethod", func(t *testing.T) {
		c, err := newDoc(func(d *Document) { d.TokenEndpointAuthMethod = "" }).ToClient()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ClientType != clientv1.ClientType_CLIENT_TYPE_PUBLIC {
			t.Errorf("client_type = %v", c.ClientType)
		}
	})

	t.Run("AuthMethodNoneIsPublic", func(t *testing.T) {
		c, err := newDoc(func(d *Document) { d.TokenEndpointAuthMethod = oidc.AuthMethodNone }).ToClient()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ClientType != clientv1.ClientType_CLIENT_TYPE_PUBLIC {
			t.Errorf("client_type = %v", c.ClientType)
		}
	})

	forbiddenAuthMethods := map[string]string{
		"client_secret_post":  oidc.AuthMethodClientSecretPost,
		"client_secret_basic": oidc.AuthMethodClientSecretBasic,
		"client_secret_jwt":   oidc.AuthMethodClientSecretJWT,
	}
	for name, method := range forbiddenAuthMethods {
		t.Run("ForbiddenAuthMethod_"+name, func(t *testing.T) {
			_, err := newDoc(func(d *Document) { d.TokenEndpointAuthMethod = method }).ToClient()
			if err == nil {
				t.Fatal("expected error for shared-secret auth method")
			}
			if !strings.Contains(err.Error(), "forbidden") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}

	t.Run("ClientSecretPresent", func(t *testing.T) {
		_, err := newDoc(func(d *Document) { d.ClientSecret = "s3cr3t" }).ToClient()
		if err == nil {
			t.Fatal("expected error for client_secret presence")
		}
	})

	t.Run("ClientSecretExpiresAtPresent", func(t *testing.T) {
		_, err := newDoc(func(d *Document) {
			expires := int64(1577836800)
			d.ClientSecretExpiresAt = &expires
		}).ToClient()
		if err == nil {
			t.Fatal("expected error for client_secret_expires_at presence")
		}
	})

	privateJWKS := map[string]string{
		"ECPrivateD": `{"keys":[{"kty":"EC","crv":"P-256","x":"usWxHK2PmwdRMx5tCYESucbsKLUeYS2tK5AFpfMz1sc","y":"AYexF3Xl0Lo0Ol7BsaNvfW4H9OpNQ0JC6T6i5jX6CqA","d":"Vld4WXhNU0xxV2dsZ0dXT3Bqc0dJSGhPQ0dhQSJ9"}]}`,
		"RSAPrivate": `{"keys":[{"kty":"RSA","n":"0vx7agoebGcQSuuP6hT2aQ","e":"AQAB","d":"X4cTteJW9tZk","p":"83i-7I","q":"3fKQ","dp":"G4uL","dq":"JbPc","qi":"tBQI"}]}`,
		"OctKey":     `{"keys":[{"kty":"oct","k":"GS3UDzpaD7KU4bdq"}]}`,
	}
	for name, jwks := range privateJWKS {
		t.Run("PrivateJWK_"+name, func(t *testing.T) {
			_, err := newDoc(func(d *Document) { d.Jwks = json.RawMessage(jwks) }).ToClient()
			if err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}

	t.Run("UnsupportedKty", func(t *testing.T) {
		_, err := newDoc(func(d *Document) {
			d.Jwks = json.RawMessage(`{"keys":[{"kty":"mystery"}]}`)
		}).ToClient()
		if err == nil {
			t.Fatal("expected error for unsupported kty")
		}
	})

	t.Run("InvalidJWKSJSON", func(t *testing.T) {
		_, err := newDoc(func(d *Document) { d.Jwks = json.RawMessage(`{`) }).ToClient()
		if err == nil {
			t.Fatal("expected error for invalid jwks JSON")
		}
	})

	t.Run("NilDocument", func(t *testing.T) {
		var d *Document
		if _, err := d.ToClient(); err == nil {
			t.Fatal("expected error for nil document")
		}
	})
}
