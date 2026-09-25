BAZEL = bazelisk
PROTO_SRC_DIR=proto
PROTO_API_DIR=api

.PHONY: help
help: Makefile
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: buildall
buildall:
	go build ./...

.PHONY: update-go-bazel-files
update-go-bazel-files:
	$(BAZEL) run //:gazelle -- update ./

.PHONY: update-go-bazel-deps
update-go-bazel-deps:
	$(BAZEL) run //:gazelle -- update-repos -from_file=go.mod -to_macro=go_repositories.bzl%go_repositories

.PHONY: gazelle
gazelle: update-go-bazel-deps update-go-bazel-files

.PHONY: bazel-build
bazel-build:
	$(BAZEL) build //...

.PHONY: bazel-test
bazel-test:
	$(BAZEL) test //...

.PHONY: bazel-test-nocache
bazel-test-nocache:
	$(BAZEL) test --cache_test_results=no //...

.PHONY: install-tools
install-tools:
	go generate ./tools.go

.PHONY: code-format
code-format:
	gofumpt -w -l .
	gci write --Section Standard --Section Default --Section "Prefix(zntr.io/solid)" .

.PHONY: regenerate-api
regenerate-api:
	rm -rf $(PROTO_API_DIR) 2>/dev/null
	mkdir $(PROTO_API_DIR)
	cd $(PROTO_SRC_DIR) && buf dep update && buf generate
