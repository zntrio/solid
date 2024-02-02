package verifiable

import (
	"context"
	"errors"
	"fmt"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/sdk/token"
)

func Token(source UUIDGeneratorFunc, secretKey []byte) token.Generator {
	return &tokenGenerator{
		generator: UUIDGenerator(source, secretKey),
	}
}

type tokenGenerator struct {
	generator Generator
}

func (c *tokenGenerator) Generate(_ context.Context, t *tokenv1.Token) (string, error) {
	// Check arguments
	switch {
	case c.generator == nil:
		return "", errors.New("the generator instance is nil")
	case t == nil:
		return "", errors.New("token must not be nil")
	}

	// Prepare token generation options
	opts := []GenerateOption{}
	switch t.TokenType {
	case tokenv1.TokenType_TOKEN_TYPE_ACCESS_TOKEN:
		opts = append(opts, WithTokenPrefix("sldat"))
	case tokenv1.TokenType_TOKEN_TYPE_REFRESH_TOKEN:
		opts = append(opts, WithTokenPrefix("sldrt"))
	case tokenv1.TokenType_TOKEN_TYPE_PHANTOM_TOKEN:
		opts = append(opts, WithTokenPrefix("sldpt"))
	default:
	}

	// Generate token
	out, err := c.generator.Generate(opts...)
	if err != nil {
		return "", fmt.Errorf("unable to generate the token value: %w", err)
	}

	return out, nil
}
