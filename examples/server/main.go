package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	discoveryv1 "go.zenithar.org/solid/api/gen/go/oidc/discovery/v1"
	"go.zenithar.org/solid/api/oidc"
	"go.zenithar.org/solid/examples/storage/inmemory"
	"go.zenithar.org/solid/pkg/authorizationserver"
	oidc_feature "go.zenithar.org/solid/pkg/authorizationserver/features/oidc"
	"go.zenithar.org/solid/pkg/client"
	"go.zenithar.org/solid/pkg/storage"

	"github.com/golang/protobuf/ptypes/wrappers"
)

// Adapter defines http middleware contract.
// https://medium.com/@matryer/writing-middleware-in-golang-and-how-go-makes-it-so-much-fun-4375c1246e81
type Adapter func(http.Handler) http.Handler

// Adapt h with all specified adapters.
func Adapt(h http.Handler, adapters ...Adapter) http.Handler {
	for _, adapter := range adapters {
		h = adapter(h)
	}
	return h
}

// ClientAuthentication is a middleware to handle client authentication.
func ClientAuthentication(clients storage.ClientReader) Adapter {
	// Prepare client authentication
	clientAuth := client.PrivateKeyJWT(clients)

	// Return middleware
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				ctx = r.Context()
				q   = r.URL.Query()
			)

			// Process authentication
			resAuth, err := clientAuth.Authenticate(ctx, &corev1.ClientAuthenticationRequest{
				ClientAssertionType: &wrappers.StringValue{
					Value: q.Get("client_assertion_type"),
				},
				ClientAssertion: &wrappers.StringValue{
					Value: q.Get("client_assertion"),
				},
			})
			if err != nil {
				log.Println("unable to authenticate client:", err)
				json.NewEncoder(w).Encode(resAuth.GetError())
				return
			}

			// Delegate to next handler
			h.ServeHTTP(w, r)
		})
	}
}

func metadataHandler(issuer string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(&discoveryv1.ServerMetadata{
			Issuer:                             issuer,
			AuthorizationEndpoint:              fmt.Sprintf("%s/authorize", issuer),
			ResponseTypesSupported:             []string{"code"},
			GrantTypesSupported:                []string{oidc.GrantTypeClientCredentials, oidc.GrantTypeAuthorizationCode},
			TokenEndpoint:                      fmt.Sprintf("%s/token", issuer),
			TokenEndpointAuthMethodsSupported:  []string{"private_key_jwt"},
			CodeChallengeMethodsSupported:      []string{"S256"},
			PushedAuthorizationRequestEndpoint: fmt.Sprintf("%s/par", issuer),
		}); err != nil {
			http.Error(w, "unable to generate server metadata", http.StatusInternalServerError)
			return
		}
	})
}

func parHandler(as authorizationserver.AuthorizationServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only POST verb
		if r.Method != http.MethodPost {
			http.Error(w, "invalid request method", http.StatusMethodNotAllowed)
		}

		var (
			ctx = r.Context()
			q   = r.URL.Query()
		)

		// Send request to reactor
		res, err := as.Do(ctx, &corev1.RegistrationRequest{
			Client: &corev1.Client{
				ClientId: "6779ef20e75817b79602",
			},
			Request: &corev1.AuthorizationRequest{
				State:               q.Get("state"),
				Nonce:               q.Get("nonce"),
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
}

func authorizeHandler(as authorizationserver.AuthorizationServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}

func tokenHandler(as authorizationserver.AuthorizationServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			q = r.URL.Query()
		)

		// Prepare msg
		msg := &corev1.TokenRequest{
			GrantType: q.Get("grant_type"),
			Client: &corev1.Client{
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
}

func main() {
	var (
		ctx = context.Background()
	)

	// Prepare the authorization server
	as := authorizationserver.New(ctx,
		"http://localhost:8080", // Issuer
		authorizationserver.ClientReader(inmemory.Clients()),
		authorizationserver.AuthorizationRequestManager(inmemory.AuthorizationRequests()),
		authorizationserver.SessionManager(inmemory.Sessions()),
	)

	// Enable Core OIDC features
	as.Enable(oidc_feature.Core())
	as.Enable(oidc_feature.PushedAuthorizationRequest())

	// Create router
	http.Handle("/.well-known/openid-configuration", metadataHandler("http://localhost:8080"))
	http.Handle("/par", Adapt(parHandler(as), ClientAuthentication(inmemory.Clients())))
	http.Handle("/authorize", authorizeHandler(as))
	http.Handle("/token", Adapt(tokenHandler(as), ClientAuthentication(inmemory.Clients())))

	log.Fatal(http.ListenAndServe(":8080", nil))
}
