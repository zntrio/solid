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
	go generate ./tools.go

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
