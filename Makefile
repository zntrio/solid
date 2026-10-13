PROTO_SRC_DIR=proto
PROTO_API_DIR=api

.PHONY: help
help: Makefile
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: buildall
buildall:
	go build ./...

.PHONY: vulncheck
vulncheck: ## Run govulncheck on the whole module
	./bin/govulncheck ./...


.PHONY: install-tools
install-tools:
	go build -o ./bin/gci github.com/daixiang0/gci
	go build -o ./bin/gofumpt mvdan.cc/gofumpt
	go build -o ./bin/golangci-lint github.com/golangci/golangci-lint/v2/cmd/golangci-lint
	go build -o ./bin/mockgen go.uber.org/mock/mockgen
	go build -o ./bin/wwhrd github.com/frapposelli/wwhrd
	go build -o ./bin/gotestsum gotest.tools/gotestsum
	go build -o ./bin/govulncheck golang.org/x/vuln/cmd/govulncheck
	go build -o ./bin/protoc-gen-go-grpc google.golang.org/grpc/cmd/protoc-gen-go-grpc
	go build -o ./bin/protoc-gen-go google.golang.org/protobuf/cmd/protoc-gen-go

.PHONY: code-format
code-format:
	gofumpt -w -l .
	gci write --Section Standard --Section Default --Section "Prefix(zntr.io/solid)" .

.PHONY: vulncheck-install
vulncheck-install:
	go build -o ./bin/govulncheck golang.org/x/vuln/cmd/govulncheck

.PHONY: regenerate-api
regenerate-api:
	rm -rf $(PROTO_API_DIR) 2>/dev/null
	mkdir $(PROTO_API_DIR)
	cd $(PROTO_SRC_DIR) && buf dep update && buf generate
