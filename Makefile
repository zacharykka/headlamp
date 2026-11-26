BINARY := ./bin/headlamp
PKG := ./cmd/headlamp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test test-race vet run-dev clean

build:
	@mkdir -p $(dir $(BINARY))
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

vet:
	go vet ./...

run-dev:
	HEADLAMP_TSNET_ENABLED=false \
	HEADLAMP_LOCAL_LISTEN=127.0.0.1:8080 \
	HEADLAMP_DEV_MODE=true \
	go run $(PKG) serve

clean:
	rm -rf ./bin
