# syntax=docker/dockerfile:1
#
# Multi-stage build producing two minimal images (server + client) from a
# single source tree. The builder is discarded; runtime images contain only a
# statically linked binary and run as an unprivileged user.

# ---- build stage ----------------------------------------------------------
FROM golang:1.22-alpine AS builder

WORKDIR /src
# Cache dependencies independently of the source (no external deps today, but
# this keeps the layer correct if go.sum is added later).
COPY go.mod ./
RUN go mod download

COPY . .

# CGO is disabled so the binaries are fully static and can run on any base.
# -trimpath removes build-host paths; -s -w strip symbols for a smaller image.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server \
 && go build -trimpath -ldflags="-s -w" -o /out/client ./cmd/client

# ---- shared runtime base --------------------------------------------------
FROM alpine:3.19 AS base
# Create an unprivileged system user (uid/gid 10001) and drop to it.
RUN addgroup -S -g 10001 app && adduser -S -u 10001 -G app app
USER 10001:10001

# ---- server image ---------------------------------------------------------
FROM base AS server
COPY --from=builder /out/server /usr/local/bin/server
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/server"]

# ---- client image ---------------------------------------------------------
FROM base AS client
COPY --from=builder /out/client /usr/local/bin/client
ENTRYPOINT ["/usr/local/bin/client"]
