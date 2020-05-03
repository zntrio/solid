package authorization

import (
	"context"

	"github.com/dchest/uniuri"
)

const (
	// DefaultAuthorizationCodeLen defines default auhtorization code length.
	DefaultAuthorizationCodeLen = 16
)

// Default returns the default authorization code generator.
func Default() CodeGenerator {
	return &codeGenerator{}
}

// -----------------------------------------------------------------------------

type codeGenerator struct {
}

func (c *codeGenerator) Generate(_ context.Context) (string, error) {
	code := uniuri.NewLen(DefaultAuthorizationCodeLen)
	return code, nil
}
