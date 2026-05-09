.PHONY: build test lint run dev tidy sqlc sqlc-diff

GO ?= go
HOOKS_BIN := ./bin/hooks
HOOKSCTL_BIN := ./bin/hooksctl

build:
	@mkdir -p bin
	$(GO) build -o $(HOOKS_BIN) ./cmd/hooks
	$(GO) build -o $(HOOKSCTL_BIN) ./cmd/hooksctl

test:
	$(GO) test ./...

lint: sqlc-diff
	$(GO) vet ./...
	$(GO) tool golangci-lint run ./...

sqlc:
	$(GO) tool sqlc generate

sqlc-diff:
	$(GO) tool sqlc diff

tidy:
	$(GO) mod tidy

run: build
	$(HOOKS_BIN)

dev: build
	$(HOOKS_BIN) --dev
