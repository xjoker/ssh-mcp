.PHONY: build release test vet check-version check-deps check-no-insecure check all

BIN := bin/ssh-mcp
PKG := ./...

# Version stamping. Single source of truth = the root VERSION file (format
# YYYYMMDD.V; bump same-day at release, `.V` increments intra-day). `make
# build` marks local dev builds with a -dev suffix so they rank below the
# tagged release and receive pre-release updates; `make release` (and CI,
# which stamps from the git tag matching VERSION) use the bare version.

build: check-version
	@VERSION="$$(go run ./cmd/version-check)-dev"; \
	COMMIT="$$(git rev-parse --short HEAD)"; \
	go build -trimpath \
		-ldflags="-X main.version=$$VERSION -X main.commit=$$COMMIT" \
		-o $(BIN) ./cmd/ssh-mcp

# release: strict build for tagged release artefacts. Refuses to build
# from a dirty tree so the resulting binary's `version` output matches a
# real tag in git.
release: check-version
	@test -z "$$(git status --porcelain)" || \
		(echo "release: refusing to build with staged, unstaged, or untracked changes"; exit 1)
	@set -e; \
	TAG="$$(git describe --tags --exact-match HEAD 2>/dev/null)" || \
		(echo "release: HEAD must have an exact stable release tag"; exit 1); \
	VERSION="$$(go run ./cmd/version-check --channel stable --tag "$$TAG")" || exit 1; \
	COMMIT="$$(git rev-parse --short HEAD)"; \
	go build -trimpath \
		-ldflags="-X main.version=$$VERSION -X main.commit=$$COMMIT" \
		-o $(BIN) ./cmd/ssh-mcp; \
	ACTUAL="$$($(BIN) version | head -n 1)"; \
	EXPECTED="ssh-mcp $$VERSION (commit $$COMMIT)"; \
	test "$$ACTUAL" = "$$EXPECTED" || \
		(echo "release: version mismatch: got '$$ACTUAL', want '$$EXPECTED'"; exit 1)

vet:
	go vet $(PKG)

test:
	go test -race $(PKG)

check-version:
	go run ./cmd/version-check

check-deps:
	bash scripts/check-deps.sh

check-no-insecure:
	bash scripts/check-no-insecure.sh

check: check-version vet check-deps check-no-insecure test

all: check build
