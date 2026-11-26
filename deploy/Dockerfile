# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/headlamp \
    ./cmd/headlamp

# Prepare non-root writable /data directory for tsnet state, master.key, and SQLite DB.
RUN mkdir -p /data && chmod 0700 /data

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/headlamp /usr/local/bin/headlamp
COPY --from=builder --chown=65532:65532 /data /data

ENV HEADLAMP_STATE_DIR=/data \
    HEADLAMP_STORAGE_DSN=/data/headlamp.db \
    HEADLAMP_LOCAL_LISTEN=:8080

VOLUME ["/data"]
EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/headlamp"]
CMD ["serve"]
