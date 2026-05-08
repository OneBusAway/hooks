.PHONY: build test lint run dev tidy

GO ?= go
HOOKS_BIN := ./bin/hooks
HOOKSCTL_BIN := ./bin/hooksctl

build:
	@mkdir -p bin
	$(GO) build -o $(HOOKS_BIN) ./cmd/hooks
	$(GO) build -o $(HOOKSCTL_BIN) ./cmd/hooksctl

test:
	$(GO) test ./...

lint:
	golangci-lint run ./...

tidy:
	$(GO) mod tidy

run: build
	$(HOOKS_BIN)

dev: build
	$(HOOKS_BIN) --dev
