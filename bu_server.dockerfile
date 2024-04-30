FROM node:20-slim AS node-build
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable
COPY ./frontend /app

WORKDIR /app

RUN pnpm install --frozen-lockfile
RUN pnpm run build

FROM golang:1.22.2-alpine3.19 as builder
ENV GO111MODULE=on CGO_ENABLED=0 GOPROXY=https://proxy.golang.org,direct

RUN apk add --no-cache bash binutils ca-certificates curl git tzdata

# setup the working directory
WORKDIR /app/src

# Download dependencies
COPY go.mod /app/src/
COPY go.sum /app/src/
RUN go mod download

# add source code
COPY . /app/src/

# add frontend code
COPY --from=node-build /app/dist /app/src/frontend/dist

# build the binary
RUN go build -ldflags='-w -s -extldflags "-static"' -a -o /go/bin/bu_server ./app/bu_server

# FROM scratch
FROM alpine:3.19

ARG APPHOME=/app
ENV PATH=$APPHOME:$PATH

WORKDIR $APPHOME

COPY --from=builder /usr/local/go/lib/time/zoneinfo.zip /usr/local/go/lib/time/zoneinfo.zip
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/bin/bu_server $APPHOME/bu_server
COPY --from=builder /app/src/app/bu_server/config.yaml $APPHOME/config.yaml
COPY --from=builder /app/src/pkg/bu_server/storage/postgres/migrations $APPHOME/migrations

EXPOSE 8080 8081

