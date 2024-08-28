FROM golang:1.22.2-alpine3.19 AS builder

ENV GOMODCACHE=/go/pkg/mod
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    GOPROXY=https://proxy.golang.org,direct

RUN apk add --no-cache \
    bash \
    binutils \
    ca-certificates \
    curl \
    git \
    tzdata

WORKDIR /app/src

COPY go.mod .
COPY go.sum .
RUN --mount=type=cache,id=go,target=/go/pkg/mod go mod download

COPY . .

RUN --mount=type=cache,id=go,target=/go/pkg/mod go build -o /app/bin/relay_server ./app/relay_server

# From scratch
FROM alpine:3.19

ARG APPHOME=/app
ENV PATH=$APPHOME:$PATH GIN_MODE=release

WORKDIR $APPHOME

COPY --from=builder /usr/local/go/lib/time/zoneinfo.zip /usr/local/go/lib/time/zoneinfo.zip
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/bin/relay_server $APPHOME/relay_server
COPY --from=builder /app/src/app/relay_server/config.yaml $APPHOME/config.yaml
COPY --from=builder /app/src/pkg/relay/server/storage/postgres/migrations/*up.sql $APPHOME/migrations/
COPY --from=builder /app/src/pkg/relay/server/storage/postgres/migrations/*down.sql $APPHOME/migrations/
