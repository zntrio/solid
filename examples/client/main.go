package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	"github.com/dchest/uniuri"
	"github.com/kr/session"
	"go.zenithar.org/solid/pkg/client"
)

type sessionObject struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
}

var clientPrivateKey = []byte(`{"kty": "EC","d": "olYJLJ3aiTyP44YXs0R3g1qChRKnYnk7GDxffQhAgL8","use": "sig","crv": "P-256","x": "h6jud8ozOJ93MvHZCxvGZnOVHLeTX-3K9LkAvKy1RSs","y": "yY0UQDLFPM8OAgkOYfotwzXCGXtBYinBk1EURJQ7ONk","alg": "ES256"}`)

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
		// Prepare client assertion
		assertion, err := solidClient.Assertion()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Generate state
		state := uniuri.NewLen(32)

		// Create authorization request
		res, err := solidClient.CreateRequestURI(r.Context(), assertion, state)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Generate authentication url
		authURL, err := solidClient.AuthenticationURL(res.RequestURI)
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

func callback(solidClient client.Client, config *session.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			ctx      = r.Context()
			q        = r.URL.Query()
			codeRaw  = q.Get("code")
			stateRaw = q.Get("state")
		)

		// Retrieve session
		var sess sessionObject
		if err := session.Get(r, &sess, config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Check state
		if sess.State != stateRaw {
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
		t, err := solidClient.ExchangeCode(ctx, assertion, codeRaw, sess.CodeVerifier)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if t == nil {
			http.Error(w, "unable to retrieve token", http.StatusInternalServerError)
			return
		}

		// Dump token
		http.Redirect(w, r, fmt.Sprintf("/#_access_token=%s", t.AccessToken), http.StatusFound)
	})
}

func main() {
	// Build client
	solidClient := client.New(client.Options{
		Audience:    "NYxFyoSuuRGXItTbX",
		ClientID:    "6779ef20e75817b79602",
		Issuer:      "http://127.0.0.1:8080",
		JWK:         clientPrivateKey,
		RedirectURI: "http://127.0.0.1:8085/cb",
		Scopes:      []string{"user profile email offline_access"},
	})

	sessions := &session.Config{
		Name:     "_solid_session",
		HTTPOnly: true,
		Secure:   false,
		Path:     "/",
		Keys:     secretKeys,
	}
	http.Handle("/login", intention(solidClient, sessions))
	http.Handle("/cb", callback(solidClient, sessions))

	log.Fatal(http.ListenAndServe(":8085", nil))
}
