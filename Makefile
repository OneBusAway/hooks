.PHONY: build install test lint run dev tidy sqlc sqlc-diff docker-build docker-run docker-test

GO ?= go
HOOKS_BIN := ./bin/hooks
HOOKSCTL_BIN := ./bin/hooksctl

DOCKER ?= docker
DOCKER_IMAGE ?= hooks
DOCKER_TAG ?= dev

build:
	@mkdir -p bin
	$(GO) build -o $(HOOKS_BIN) ./cmd/hooks
	$(GO) build -o $(HOOKSCTL_BIN) ./cmd/hooksctl

# Installs hooksctl into $GOBIN if set, else $GOPATH/bin (default ~/go/bin).
# Override the destination with `GOBIN=/some/dir make install`.
install:
	$(GO) install ./cmd/hooksctl

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

docker-build:
	$(DOCKER) build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# RENDER_WEBHOOK_SECRET must be in the caller's env (or pass --env-file).
docker-run: docker-build
	mkdir -p ./hooks-data
	$(DOCKER) run --rm -it \
		-p 8080:8080 \
		-v $(CURDIR)/hooks-data:/data \
		-e RENDER_WEBHOOK_SECRET \
		-e HOOKS_PUBLIC_URL \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

docker-test:
	$(GO) test -tags=docker -count=1 ./dockertest/...
