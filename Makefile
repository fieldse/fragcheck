BINARY := linux-vuln-auditor
PKG    := ./cmd/linux-vuln-auditor
BIN    := bin

# Linux cross-compile target (override ARCH as needed, e.g. amd64).
ARCH ?= arm64

.DEFAULT_GOAL := build

.PHONY: build
build: ## Build the binary into bin/
	go build -o $(BIN)/$(BINARY) $(PKG)

.PHONY: run
run: ## Run the auditor (refuses cleanly off Linux / non-root)
	go run $(PKG)

.PHONY: test
test: ## Run the full test suite
	go test ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: fmt
fmt: ## Format all Go source
	go fmt ./...

.PHONY: tidy
tidy: ## Tidy module dependencies
	go mod tidy

.PHONY: check
check: fmt vet test ## Format, vet, and test

.PHONY: linux
linux: ## Cross-compile a Linux binary into bin/lva-linux
	GOOS=linux GOARCH=$(ARCH) go build -o $(BIN)/lva-linux $(PKG)

.PHONY: e2e
e2e: linux ## Run the Linux binary as root in an Ubuntu container
	podman run --rm -v "$(PWD)/$(BIN)/lva-linux:/lva:ro" ubuntu:22.04 /lva

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN)

.PHONY: help
help: ## List available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
