package token

import "errors"

// ErrInvalidTokenSignature is raised when token is signed with a private key
// where the public key is not known by the keyset.
var ErrInvalidTokenSignature = errors.New("invalid token signature")
