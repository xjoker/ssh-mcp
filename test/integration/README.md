# Integration tests

End-to-end smoke tests that drive the bridge over its real MCP stdio
transport against two `linuxserver/openssh-server` containers.

## Prerequisites

- Docker (compose v2)
- Go 1.22+
- A built binary at `bin/mcp-ssh-bridge`

## Setup

```bash
# 1. Generate a throwaway SSH key for the key-auth container
ssh-keygen -t ed25519 -N '' -f test/integration/test_key -C test@msb-integration

# 2. Bring up the containers (publishes 22021 + 22022 on localhost)
docker compose -f test/integration/docker-compose.yml up -d

# 3. Build the bridge
go build -trimpath -o bin/mcp-ssh-bridge ./cmd/mcp-ssh-bridge

# 4. Trust the host keys once
MCP_SSH_BRIDGE_CONFIG=$PWD/test/integration/config.toml \
  ./bin/mcp-ssh-bridge trust test-pwd
MCP_SSH_BRIDGE_CONFIG=$PWD/test/integration/config.toml \
  ./bin/mcp-ssh-bridge trust test-key
```

## Run

```bash
go test -tags=integration -count=1 -timeout 180s -v ./test/integration/...
```

Coverage:

- `ssh_exec` (password auth, key auth + cwd resolution)
- `sftp_list` (remote root)
- `session_start` / `session_send` / `session_close` round-trip
  (validates sentinel-based exit code propagation)
- `ssh_group_exec` over both servers
- `audit_query`
- `list_servers` (asserts no password leakage)

## Teardown

```bash
docker compose -f test/integration/docker-compose.yml down -v
rm -f test/integration/test_key test/integration/test_key.pub
# Optionally strip the host-key entries this leaves in ~/.ssh/known_hosts:
#   grep -v '\[127.0.0.1\]:2202[12]' ~/.ssh/known_hosts > /tmp/kh \
#     && mv /tmp/kh ~/.ssh/known_hosts
```

## Notes

- `USER_PASSWORD=test-password-marker` in `docker-compose.yml` is a
  throwaway value tied to ephemeral test containers; never reuse.
- `key_path` may be relative; the bridge resolves it against the
  directory containing the config file (or `~` against `$HOME`).
