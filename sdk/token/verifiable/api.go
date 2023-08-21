package verifiable

import (
	"errors"
	"regexp"
)

var (
	defaultSeparator    = "_"
	nonAuthorizedChars  = regexp.MustCompile("[^a-z0-9-]")
)

// ErrTokenNotAuthenticated is raised when you try to validate a non compliant value.
var ErrTokenNotAuthenticated = errors.New("token: value could not be authenticated")

// Generator describes token generator contract.
type Generator interface {
	Generate(...GenerateOption) (string, error)
}

// Verifier describes token verification contract.
type Verifier interface {
	Verify(t string) error
}

// Extractor describes content extractor for wrapped values.
type Extractor[T any] interface {
	Extract(t string) (T, error)
}

type VerifiableGenerator interface {
	Generator
	Verifier
}