GO ?= go

BINS := bin/coordinator bin/relay bin/natbox bin/agent

# All Go sources in the module drive every binary target so that edits
# anywhere (internal/ + cmd/) trigger a rebuild.
GOFILES := $(shell find cmd internal -name '*.go' -type f)

.PHONY: all build test vet fmt clean demo fuzz-smoke

all: build

build: $(BINS)

bin/coordinator: $(GOFILES)
	@mkdir -p bin
	$(GO) build -o $@ ./cmd/coordinator

bin/relay: $(GOFILES)
	@mkdir -p bin
	$(GO) build -o $@ ./cmd/relay

bin/natbox: $(GOFILES)
	@mkdir -p bin
	$(GO) build -o $@ ./cmd/natbox

bin/agent: $(GOFILES)
	@mkdir -p bin
	$(GO) build -o $@ ./cmd/agent

test:
	$(GO) test -race ./internal/...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

clean:
	rm -rf bin

demo: build
	./scripts/demo.sh

# TUN end-to-end verification (requires root; re-execs via sudo).
tun-demo: build
	./scripts/tun-demo.sh

# Short fuzz smoke over every parser package (10s each).
fuzz-smoke:
	$(GO) test -run='^$$' -fuzz=Fuzz -fuzztime=10s ./internal/record ./internal/relay ./internal/nat ./internal/stun ./internal/protocol