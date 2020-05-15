package handlers

import (
	"log"
	"net/http"

	"github.com/golang/protobuf/ptypes/wrappers"
	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/pkg/authorizationserver"
	"go.zenithar.org/solid/pkg/clientauthentication"
	"go.zenithar.org/solid/pkg/rfcerrors"
)

// TokenIntrospection handles token introspection HTTP requests.
func TokenIntrospection(as authorizationserver.AuthorizationServer) http.Handler {
	type response struct {
		Active bool `json:"active"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			q             = r.URL.Query()
			ctx           = r.Context()
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
		msg := &corev1.TokenIntrospectionRequest{
			Client: client,
			Token:  token,
		}
		if tokenTypeHint != "" {
			msg.TokenTypeHint = &wrappers.StringValue{
				Value: tokenTypeHint,
			}
		}

		// Send request to reactor
		res, err := as.Do(ctx, msg)
		introRes, ok := res.(*corev1.TokenIntrospectionResponse)
		if !ok {
			withJSON(w, r, http.StatusInternalServerError, rfcerrors.ServerError(""))
			return
		}
		if err != nil {
			log.Println("unable to process introspection request: %w", err)
			withJSON(w, r, http.StatusBadRequest, introRes.Error)
			return
		}

		// Send json reponse
		withJSON(w, r, http.StatusOK, &response{
			Active: introRes.Token.Status == corev1.TokenStatus_TOKEN_STATUS_ACTIVE,
		})
	})
}
