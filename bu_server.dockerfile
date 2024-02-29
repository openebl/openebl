FROM golang:1.21.1-alpine3.18 as builder

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

# setup the working directory
WORKDIR /app/src

# Download dependencies
COPY go.mod /app/src/
COPY go.sum /app/src/
RUN go mod download

# add source code
COPY . /app/src/

# build the binary
RUN go build -ldflags='-w -s -extldflags "-static"' -a -o /go/bin/bu_server ./app/bu_server

# FROM scratch
FROM alpine:3.18

ARG APPHOME=/app
ENV PATH=$APPHOME:$PATH

WORKDIR $APPHOME

COPY --from=builder /usr/local/go/lib/time/zoneinfo.zip /usr/local/go/lib/time/zoneinfo.zip
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/bin/bu_server $APPHOME/bu_server
COPY --from=builder /app/src/app/bu_server/config.yaml $APPHOME/config.yaml
COPY --from=builder /app/src/pkg/bu_server/storage/postgres/migrations $APPHOME/migrations

EXPOSE 8080 8081

