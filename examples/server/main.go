package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/api/oidc"
	"go.zenithar.org/solid/examples/storage/inmemory"
	"go.zenithar.org/solid/pkg/authorizationserver"
	oidc_feature "go.zenithar.org/solid/pkg/authorizationserver/features/oidc"

	"github.com/golang/protobuf/ptypes/wrappers"
)

func main() {
	var (
		ctx = context.Background()
	)

	// Prepare the authorization server
	as := authorizationserver.New(ctx,
		"http://localhost", // Issuer
		authorizationserver.ClientReader(inmemory.Clients()),
		authorizationserver.AuthorizationRequestManager(inmemory.AuthorizationRequests()),
		authorizationserver.SessionManager(inmemory.Sessions()),
	)

	// Enable Core OIDC features
	as.Enable(oidc_feature.Core())
	as.Enable(oidc_feature.PushedAuthorizationRequest())

	// Create router
	http.HandleFunc("/par", func(w http.ResponseWriter, r *http.Request) {
		// Only POST verb
		if r.Method != http.MethodPost {
			http.Error(w, "invalid request method", http.StatusMethodNotAllowed)
		}

		var (
			q = r.URL.Query()
		)

		// Send request to reactor
		res, err := as.Do(r.Context(), &corev1.RegistrationRequest{
			Request: &corev1.AuthorizationRequest{
				State:               q.Get("state"),
				ClientId:            q.Get("client_id"),
				Scope:               q.Get("scope"),
				RedirectUri:         q.Get("redirect_uri"),
				ResponseType:        q.Get("response_type"),
				CodeChallenge:       q.Get("code_challenge"),
				CodeChallengeMethod: q.Get("code_challenge_method"),
			},
		})
		if err != nil {
			log.Println("unable to register authorization request:", err)
			json.NewEncoder(w).Encode(res.(*corev1.RegistrationResponse).GetError())
			return
		}

		json.NewEncoder(w).Encode(res)
	})

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// Only GET verb
		if r.Method != http.MethodGet {
			http.Error(w, "invalid request method", http.StatusMethodNotAllowed)
		}

		var (
			q = r.URL.Query()
		)

		// Send request to reactor
		res, err := as.Do(r.Context(), &corev1.AuthorizationRequest{
			RequestUri: &wrappers.StringValue{
				Value: q.Get("request_uri"),
			},
		})
		if err != nil {
			log.Println("unable to process authorization request:", err)
			json.NewEncoder(w).Encode(res.(*corev1.AuthorizationResponse).GetError())
			return
		}

		json.NewEncoder(w).Encode(res)
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		var (
			q = r.URL.Query()
		)

		// Prepare msg
		msg := &corev1.TokenRequest{
			GrantType: q.Get("grant_type"),
			Client: &corev1.ClientAuthentication{
				// Force client id while no client authentication yet
				ClientId: "6779ef20e75817b79602",
			},
		}

		switch q.Get("grant_type") {
		case oidc.GrantTypeAuthorizationCode:
			msg.Grant = &corev1.TokenRequest_AuthorizationCode{
				AuthorizationCode: &corev1.GrantAuthorizationCode{
					Code:         q.Get("code"),
					CodeVerifier: q.Get("code_verifier"),
					RedirectUri:  q.Get("redirect_uri"),
				},
			}
		case oidc.GrantTypeClientCredentials:
			msg.Grant = &corev1.TokenRequest_ClientCredentials{
				ClientCredentials: &corev1.GrantClientCredentials{},
			}
		case oidc.GrantTypeDeviceCode:
			msg.Grant = &corev1.TokenRequest_DeviceCode{
				DeviceCode: &corev1.GrantDeviceCode{},
			}
		case oidc.GrantTypeRefreshToken:
			msg.Grant = &corev1.TokenRequest_RefreshToken{
				RefreshToken: &corev1.GrantRefreshToken{
					RefreshToken: q.Get("refresh_token"),
				},
			}
		}

		// Send request to reactor
		res, err := as.Do(r.Context(), msg)
		if err != nil {
			log.Println("unable to process authorization request: %w", err)
			json.NewEncoder(w).Encode(res.(*corev1.TokenResponse).GetError())
			return
		}

		json.NewEncoder(w).Encode(res.(*corev1.TokenResponse).GetOpenid())
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
