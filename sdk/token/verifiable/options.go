package verifiable

import "strings"

// GenerateOption is used to set up the token generation process.
type GenerateOption func(*generateOption)

// generateOption holds the generation settings.
type generateOption struct {
	prefix string
}

// WithTokenPrefix prepends the given prefix to the token generation so that it
// will be covered by the checksum.
//
// Prefix must match [a-z0-9-]+ regular expression (lowercase kebab case).
func WithTokenPrefix(value string) GenerateOption {
	return func(o *generateOption) {
		o.prefix = strings.TrimSpace(strings.ToLower(value))
	}
}
