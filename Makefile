.PHONY: build release test vet check-deps check-no-insecure check all

BIN := bin/ssh-mcp
PKG := ./...

# Version stamping. Single source of truth = the root VERSION file (format
# YYYYMMDD.V; bump same-day at release, `.V` increments intra-day). `make
# build` marks local dev builds with a -dev suffix so they rank below the
# tagged release and receive pre-release updates; `make release` (and CI,
# which stamps from the git tag matching VERSION) use the bare version.
VERSION ?= $(shell cat VERSION 2>/dev/null || echo 0.0.0)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

build:
	go build -trimpath -ldflags '-X main.version=$(VERSION)-dev -X main.commit=$(COMMIT)' -o $(BIN) ./cmd/ssh-mcp

# release: strict build for tagged release artefacts. Refuses to build
# from a dirty tree so the resulting binary's `version` output matches a
# real tag in git.
release:
	@git diff --quiet || (echo "release: refusing to build with uncommitted changes"; exit 1)
	go build -trimpath -ldflags '-X main.version=$(VERSION) -X main.commit=$(COMMIT)' -o $(BIN) ./cmd/ssh-mcp
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
