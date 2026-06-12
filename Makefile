BINARY := linux-vuln-auditor
PKG    := ./cmd/linux-vuln-auditor
BIN    := bin

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

.PHONY: linux-amd64
linux-amd64: ## Cross-compile a Linux x86-64 binary
	GOOS=linux GOARCH=amd64 go build -o $(BIN)/$(BINARY)-linux-amd64 $(PKG)

.PHONY: linux-arm64
linux-arm64: ## Cross-compile a Linux arm64 binary
	GOOS=linux GOARCH=arm64 go build -o $(BIN)/$(BINARY)-linux-arm64 $(PKG)

.PHONY: linux
linux: linux-amd64 linux-arm64 ## Cross-compile both Linux architectures

.PHONY: e2e
e2e: linux-arm64 ## Run the arm64 Linux binary as root in an Ubuntu container
	podman run --rm -v "$(PWD)/$(BIN)/$(BINARY)-linux-arm64:/lva:ro" ubuntu:22.04 /lva

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN)

.PHONY: help
help: ## List available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
