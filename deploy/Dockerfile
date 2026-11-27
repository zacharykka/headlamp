# syntax=docker/dockerfile:1

FROM node:22-alpine AS web-builder

WORKDIR /src/web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN rm -rf ./web/dist
COPY --from=web-builder /src/web/dist ./web/dist

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
    -o /out/headlamp \
    ./cmd/headlamp

# Prepare non-root writable /data directory for tsnet state, master.key, and SQLite DB.
RUN mkdir -p /data && chmod 0700 /data

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/headlamp /usr/local/bin/headlamp
COPY --from=builder --chown=65532:65532 /data /data

# Default to pure tsnet operation. Set HEADLAMP_LOCAL_LISTEN explicitly only if you
# need an additional local HTTP listener (e.g. for health probes or static API tokens).
ENV HEADLAMP_STATE_DIR=/data \
    HEADLAMP_STORAGE_DSN=/data/headlamp.db

VOLUME ["/data"]
# Optional local HTTP listener port when HEADLAMP_LOCAL_LISTEN is explicitly configured.
EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/headlamp"]
CMD ["serve"]
