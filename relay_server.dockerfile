FROM golang:1.21.3-alpine3.18 AS builder

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
RUN go mod download

COPY . .

RUN go build -o /app/bin/relay_server ./app/relay_server

# From scratch
FROM alpine:3.18

ARG APP_HOME=/app
ENV PATH=$APP_HOME:$PATH GIN_MODE=release

WORKDIR $APP_HOME

COPY --from=builder /usr/local/go/lib/time/zoneinfo.zip /usr/local/go/lib/time/zoneinfo.zip
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/bin/relay_server $APP_HOME/relay_server
COPY --from=builder /app/src/app/relay_server/config.yaml $APP_HOME/config.yaml
COPY --from=builder /app/src/pkg/relay/server/storage/postgres/migrations/*up.sql $APP_HOME/migrations/
COPY --from=builder /app/src/pkg/relay/server/storage/postgres/migrations/*down.sql $APP_HOME/migrations/
