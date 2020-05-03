package rfcerrors

import (
	"github.com/golang/protobuf/ptypes/wrappers"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
)

// ServerError returns a compliant `server_error` error.
func ServerError(state string) *corev1.Error {
	return &corev1.Error{
		State: state,
		Err:   "server_error",
		ErrorDescription: &wrappers.StringValue{
			Value: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
	}
}

// InvalidRequest returns a compliant ìnvalid_request` error.
func InvalidRequest(state string) *corev1.Error {
	return &corev1.Error{
		State: state,
		Err:   "invalid_request",
		ErrorDescription: &wrappers.StringValue{
			Value: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
		},
	}
}

// InvalidScope returns a compliant `invalid_scope` error.
func InvalidScope(state string) *corev1.Error {
	return &corev1.Error{
		State: state,
		Err:   "invalid_scope",
		ErrorDescription: &wrappers.StringValue{
			Value: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
		},
	}
}
