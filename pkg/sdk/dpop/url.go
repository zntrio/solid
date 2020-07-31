package dpop

import (
	"fmt"
	"net/http"
)

// CleanURL returns a cleanurl for DPoP proof.
func CleanURL(r *http.Request) string {
	// Prepare the url
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwardScheme := r.Header.Get("X-Forwarded-Scheme"); forwardScheme != "" {
		scheme = forwardScheme
	}

	// Assemble response
	return fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)
}
