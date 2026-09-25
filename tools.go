// Licensed to SolID under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. SolID licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build tools
// +build tools

package tools

import (
	_ "github.com/daixiang0/gci"
	_ "github.com/frapposelli/wwhrd"
	_ "github.com/golangci/golangci-lint/v2/cmd/golangci-lint"
	_ "go.uber.org/mock/mockgen"
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
//go:generate go build -v -o=./bin/mockgen go.uber.org/mock/mockgen
//go:generate go build -v -o=./bin/golangci-lint github.com/golangci/golangci-lint/v2/cmd/golangci-lint
//go:generate go build -v -o=./bin/gotestsum gotest.tools/gotestsum
//go:generate go build -v -o=./bin/gofumpt mvdan.cc/gofumpt
