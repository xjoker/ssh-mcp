.PHONY: build release test vet check-deps check-no-insecure check all

BIN := bin/ssh-mcp
PKG := ./...

# Version stamping. By default we read the most recent annotated tag (or
# fall back to "0.0.1-dev" on a clean checkout with no tags). Override
# with `make build VERSION=0.0.1` for release artefacts.
VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo 0.0.1-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT)

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/ssh-mcp

# release: strict build for tagged release artefacts. Refuses to build
# from a dirty tree so the resulting binary's `version` output matches a
# real tag in git.
release:
	@git diff --quiet || (echo "release: refusing to build with uncommitted changes"; exit 1)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/ssh-mcp
	@$(BIN) version

vet:
	go vet $(PKG)

test:
	go test -race $(PKG)

check-deps:
	bash scripts/check-deps.sh

check-no-insecure:
	bash scripts/check-no-insecure.sh

check: vet check-deps check-no-insecure test

all: check build
