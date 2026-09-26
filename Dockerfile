FROM golang:1.26.8-alpine3.24@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS builder

WORKDIR /src

ENV CGO_ENABLED=0 GOTOOLCHAIN=local

COPY go.mod go.sum ./
COPY things-cloud-sdk/go.mod things-cloud-sdk/go.sum ./things-cloud-sdk/
RUN go mod download
COPY *.go ./
COPY things-cloud-sdk ./things-cloud-sdk
RUN go build -trimpath -ldflags="-s -w" -o /out/things-mcp .

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN apk add --no-cache ca-certificates su-exec \
    && addgroup -S things \
    && adduser -S -D -H -u 10001 -G things things \
    && install -d -o things -g things -m 0700 /data

COPY --from=builder --chown=things:things /out/things-mcp /usr/local/bin/things-mcp
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

EXPOSE 8080

ENV PORT=8080
ENV DATA_DIR=/data

VOLUME ["/data"]

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["things-mcp"]
