# syntax=docker/dockerfile:1.7

# --- builder ---------------------------------------------------------------
# Pin to the toolchain declared in go.mod (1.26). Bumping go.mod's `go`
# directive without bumping this tag will break reproducibility.
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Cache modules in a layer separate from the source tree so source-only
# changes don't bust the (large) module download.
COPY go.mod go.sum ./
RUN go mod download

# Selective COPY rather than `COPY . .` — keeps the build context tight and
# is explicit about what lands in the image. .dockerignore is a backstop, but
# being explicit here is the primary defence against accidentally shipping
# secrets, local state, or .git.
COPY cmd/      ./cmd/
COPY internal/ ./internal/

# Pure-Go build: modernc.org/sqlite means we don't need cgo.
# -trimpath strips local filesystem paths from the binary; -ldflags reduces
# size by stripping the symbol table. BuildKit cache mounts persist the Go
# build/module cache across docker builds, so unchanged-tree rebuilds skip
# recompilation.
ENV CGO_ENABLED=0
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -trimpath -ldflags="-s -w" -o /out/hooks    ./cmd/hooks && \
    go build -trimpath -ldflags="-s -w" -o /out/hooksctl ./cmd/hooksctl

# --- runtime ---------------------------------------------------------------
# Alpine: small enough to keep the attack surface tight; debuggable enough
# to `docker exec` into for triage. The HEALTHCHECK below depends on
# busybox's `wget` (provided by the base image) — do not switch to a base
# without busybox without also updating the HEALTHCHECK CMD.
FROM alpine:3.20

RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 65532 hooks \
 && adduser  -S -u 65532 -G hooks -h /data hooks \
 && mkdir -p /data \
 && chown -R hooks:hooks /data

COPY --from=builder /out/hooks    /usr/local/bin/hooks
COPY --from=builder /out/hooksctl /usr/local/bin/hooksctl
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

USER hooks
WORKDIR /data
VOLUME ["/data"]

# Override the binary's `./hooks.db` default so the DB lives on the
# persistent volume rather than the ephemeral container layer.
ENV HOOKS_DATABASE_URL=/data/hooks.db

EXPOSE 8080

# Honor HOOKS_LISTEN_ADDR if the operator overrode it (e.g. render.yaml
# sets :10000 to match Render's PORT). Falls back to :8080, which matches
# the binary's DefaultListenAddr.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- "http://127.0.0.1${HOOKS_LISTEN_ADDR:-:8080}/healthz" >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
