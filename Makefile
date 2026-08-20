GO ?= go

BINS := bin/coordinator bin/relay bin/natbox bin/agent

# All Go sources in the module drive every binary target so that edits
# anywhere (internal/ + cmd/) trigger a rebuild.
GOFILES := $(shell find cmd internal -name '*.go' -type f)

.PHONY: all build test vet fmt clean demo tun-demo fuzz-smoke

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

# Short fuzz smoke over every parser package. go test only accepts -fuzz for a
# single package and a single explicit function, so iterate over each
# package/function pair (10s each).
FUZZ_PKGS := ./internal/record ./internal/relay ./internal/nat ./internal/stun ./internal/protocol
fuzz-smoke:
	@set -e; \
	for pkg in $(FUZZ_PKGS); do \
		dir=$${pkg#./}; \
		for tf in $$dir/*_test.go; do \
			for fn in $$(grep -oE 'func Fuzz[A-Za-z0-9_]+' "$$tf" 2>/dev/null | sed 's/func //'); do \
				echo "== fuzz $$fn in $$pkg =="; \
				$(GO) test -run='^$$' -fuzz="^$$fn$$" -fuzztime=10s "$$pkg"; \
			done; \
		done; \
	done