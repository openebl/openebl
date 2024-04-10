FROM golang:1.22.1-alpine3.19 as builder
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

# build the binary
RUN go build -ldflags='-w -s -extldflags "-static"' -a -o /go/bin/cert_server ./app/cert_server

# FROM scratch
FROM alpine:3.19

ARG APPHOME=/app
ENV PATH=$APPHOME:$PATH

WORKDIR $APPHOME

COPY --from=builder /usr/local/go/lib/time/zoneinfo.zip /usr/local/go/lib/time/zoneinfo.zip
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/bin/cert_server $APPHOME/cert_server
COPY --from=builder /app/src/app/cert_server/config.yaml $APPHOME/config.yaml
COPY --from=builder /app/src/pkg/cert_server/storage/postgres/migrations $APPHOME/migrations
