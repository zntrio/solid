package handlers

import (
	"log"
	"net/http"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/pkg/authorizationserver"
	"go.zenithar.org/solid/pkg/clientauthentication"
	"go.zenithar.org/solid/pkg/rfcerrors"

	"github.com/golang/protobuf/ptypes/wrappers"
)

// TokenRevocation handles token revocation HTTP requests.
func TokenRevocation(as authorizationserver.AuthorizationServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			ctx           = r.Context()
			q             = r.URL.Query()
			token         = q.Get("token")
			tokenTypeHint = q.Get("token_type_hint")
		)

		// Retrieve client front context
		client, ok := clientauthentication.FromContext(ctx)
		if client == nil || !ok {
			withJSON(w, r, http.StatusUnauthorized, rfcerrors.InvalidClient(""))
			return
		}

		// Prepare msg
		msg := &corev1.TokenRevocationRequest{
			Client: client,
			Token:  token,
		}
		if tokenTypeHint != "" {
			msg.TokenTypeHint = &wrappers.StringValue{
				Value: tokenTypeHint,
			}
		}

		// Send request to reactor
		res, err := as.Do(r.Context(), msg)
		revoRes, ok := res.(*corev1.TokenRevocationResponse)
		if !ok {
			withJSON(w, r, http.StatusInternalServerError, rfcerrors.ServerError(""))
			return
		}
		if err != nil {
			log.Println("unable to process revocation request: %w", err)
			withJSON(w, r, http.StatusBadRequest, revoRes.Error)
			return
		}
	})
}
