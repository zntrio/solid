//go:build tools
// +build tools

package tools

import (
	_ "github.com/daixiang0/gci"
	_ "github.com/frapposelli/wwhrd"
	_ "github.com/golang/mock/mockgen"
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "google.golang.org/grpc/cmd/protoc-gen-go-grpc"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
	_ "gotest.tools/gotestsum"
	_ "mvdan.cc/gofumpt"
)

// If you want to use tools, please run the following command:
//  go generate ./tools.go
//
//go:generate go build -v -o=./bin/protoc-gen-go-grpc google.golang.org/grpc/cmd/protoc-gen-go-grpc
//go:generate go build -v -o=./bin/protoc-gen-go google.golang.org/protobuf/cmd/protoc-gen-go
//go:generate go build -v -o=./bin/gci github.com/daixiang0/gci
//go:generate go build -v -o=./bin/wwhrd github.com/frapposelli/wwhrd
//go:generate go build -v -o=./bin/mockgen github.com/golang/mock/mockgen
//go:generate go build -v -o=./bin/golangci-lint github.com/golangci/golangci-lint/cmd/golangci-lint
//go:generate go build -v -o=./bin/gotestsum gotest.tools/gotestsum
//go:generate go build -v -o=./bin/gofumpt mvdan.cc/gofumpt
