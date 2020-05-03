package authorization

import "context"

//go:generate mockgen -destination mock/codegenerator.gen.go -package mock go.zenithar.org/solid/pkg/authorization CodeGenerator

// CodeGenerator describes authorization code generator contract.
type CodeGenerator interface {
	Generate(ctx context.Context) (string, error)
}
