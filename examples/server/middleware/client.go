package middleware

import (
	"encoding/json"
	"log"
	"net/http"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/pkg/clientauthentication"
	"go.zenithar.org/solid/pkg/storage"

	"github.com/golang/protobuf/ptypes/wrappers"
)

// ClientAuthentication is a middleware to handle client authentication.
func ClientAuthentication(clients storage.ClientReader) Adapter {
	// Prepare client authentication
	clientAuth := clientauthentication.PrivateKeyJWT(clients)

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

			// Assign client to context
			ctx = clientauthentication.Inject(ctx, resAuth.Client)

			// Delegate to next handler
			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
