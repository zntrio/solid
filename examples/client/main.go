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

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"zntr.io/solid/api/oidc"
	"zntr.io/solid/pkg/client"
	"zntr.io/solid/pkg/sdk/dpop"
	"zntr.io/solid/pkg/sdk/jarm"
	"zntr.io/solid/pkg/sdk/jwsreq"

	"github.com/dchest/uniuri"
	"github.com/kr/session"
	"github.com/square/go-jose/v3"
)

type sessionObject struct {
	State        string `json:"state,omitempty"`
	Nonce        string `json:"nonce,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	AccessToken  string `json:"at,omitempty"`
	RefreshToken string `json:"rt,omitempty"`
}

var clientPrivateKey = []byte(`{
    "kty": "EC",
    "d": "Uwq56PhVB6STB8MvLQWcOsKQlZbBvWFQba8D6Uhb2qDunpzqvoNyFsnAHKS_AkQB",
    "use": "sig",
    "crv": "P-384",
    "x": "m2NDaWfRRGlCkUa4FK949uLtMqitX1lYgi8UCIMtsuR60ux3d00XBlsC6j_YDOTe",
    "y": "6vxuUq3V1aoWi4FQ_h9ZNwUsmcGP8Uuqq_YN5dhP0U8lchdmZJbLF9mPiimo_6p4",
    "alg": "ES384"
}`)

const secret = "54686520776f7264206875736b79206f726967696e617465642066726f6d2074686520776f726420726566657272696e6720746f204172637469632070656f706c6520696e2067656e6572616c2c20496e7569742028612e6b2e612e2045736b696d6f73292c202e2e2e6b6e6f776e20617320276875736b69657327"

var secretKeys []*[32]byte

func init() {
	var sk [32]byte
	secretKeyBytes, _ := hex.DecodeString(secret)
	copy(sk[:], secretKeyBytes)
	secretKeys = []*[32]byte{&sk}
}

func intention(solidClient client.Client, config *session.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Prepare client assertion
		assertion, err := solidClient.Assertion()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Generate state
		state := uniuri.NewLen(32)

		// Create authorization request
		res, err := solidClient.CreateRequestURI(ctx, assertion, state)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Generate authentication url
		authURL, err := solidClient.AuthenticationURL(ctx, res.RequestURI)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Save state in session
		if err := session.Set(w, &sessionObject{
			State:        state,
			Nonce:        res.Nonce,
			CodeVerifier: res.CodeVerifier,
		}, config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Redirect to authentication URL
		http.Redirect(w, r, authURL, http.StatusFound)
	})
}

func callback(solidClient client.Client, config *session.Config, prover dpop.Prover, jarDecoder jarm.ResponseDecoder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			ctx         = r.Context()
			q           = r.URL.Query()
			responseRaw = q.Get("response")
		)

		// Retrieve session
		var sess sessionObject
		if err := session.Get(r, &sess, config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Decode response
		response, err := jarDecoder.Decode(ctx, solidClient.ClientID(), responseRaw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Check state
		if sess.State != response.State {
			http.Error(w, "state doesn't match", http.StatusBadRequest)
			return
		}

		// Prepare client assertion
		assertion, err := solidClient.Assertion()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Exchange code with token
		t, err := solidClient.ExchangeCode(ctx, assertion, response.Code, sess.CodeVerifier)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if t == nil {
			http.Error(w, "unable to retrieve token", http.StatusInternalServerError)
			return
		}

		// Update session
		if err := session.Set(w, &sessionObject{
			AccessToken:  t.AccessToken,
			RefreshToken: t.RefreshToken,
		}, config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Dump token
		http.Redirect(w, r, "/", http.StatusFound)
	})
}

func home(config *session.Config) http.Handler {

	tmpl := template.Must(template.New("home").Parse(`<!doctype html>
	<html lang="fr">
	<head>
	  <meta charset="utf-8">
	  <title>Home</title>
	  <style>
	  code {
		background-color: #EEEEEE;
		font-family: Consolas,Menlo,Monaco,Lucida Console,Liberation Mono,DejaVu Sans Mono,Bitstream Vera Sans Mono,Courier New,monospace,serif;
	  }
	  pre {
		background-color: #EEEEEE;
		font-family: Consolas,Menlo,Monaco,Lucida Console,Liberation Mono,DejaVu Sans Mono,Bitstream Vera Sans Mono,Courier New,monospace,serif;
		margin-bottom: 10px;
		max-height: 600px;
		overflow: auto;
		padding: 5px;
		width: auto;
	  }
	  </style>
	</head>
	<body>
		<p>
			Access Token
			<pre>{{ .AccessToken }}</pre>
		</p>
		<p>
			Refresh Token
			<pre>{{ .RefreshToken }}</pre>
		</p>
	</body>
	</html>
	`))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Retrieve session
		var sess sessionObject
		if err := session.Get(r, &sess, config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Generate page
		tmpl.Execute(w, &sess)
	})
}

func main() {
	// Prover
	prover, err := dpop.DefaultProver()
	if err != nil {
		panic(err)
	}

	// JAR
	arEncoder := jwsreq.JWTAuthorizationEncoder(jose.ES384, func(_ context.Context) (*jose.JSONWebKey, error) {
		var privateKey jose.JSONWebKey

		// Decode JWK
		err := json.Unmarshal(clientPrivateKey, &privateKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decode JWK: %w", err)
		}

		// No error
		return &privateKey, nil
	})
	if err != nil {
		panic(err)
	}

	// Build client
	solidClient := client.HTTP(prover, arEncoder, &client.Options{
		Audience:    "NYxFyoSuuRGXItTbX",
		ClientID:    "6779ef20e75817b79602",
		Issuer:      "http://127.0.0.1:8080",
		JWK:         clientPrivateKey,
		RedirectURI: "http://127.0.0.1:8085/oidc/as/127.0.0.1",
		Scopes:      []string{"user", "profile", "email", oidc.ScopeOfflineAccess},
	})

	// JARM
	jarmDecoder := jarm.JWTDecoder("http://127.0.0.1:8080", func(ctx context.Context) (*jose.JSONWebKeySet, error) {
		jwks, _, err := solidClient.PublicKeys(ctx)
		if err != nil {
			return nil, err
		}
		return jwks, nil
	})

	// Cookie session
	sessions := &session.Config{
		Name:     "_solid_session",
		HTTPOnly: true,
		Secure:   false,
		Path:     "/",
		Keys:     secretKeys,
	}

	// Endpoints
	http.Handle("/", home(sessions))
	http.Handle("/login", intention(solidClient, sessions))
	http.Handle("/oidc/as/127.0.0.1", callback(solidClient, sessions, prover, jarmDecoder))

	log.Fatal(http.ListenAndServe(":8085", nil))
}
