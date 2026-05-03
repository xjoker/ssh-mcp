.PHONY: build test vet check-deps check-no-insecure check all

BIN := bin/mcp-ssh-bridge
PKG := ./...

build:
	go build -trimpath -o $(BIN) ./cmd/mcp-ssh-bridge

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
