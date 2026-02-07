# Development

Notes for people working on gadget-dns-server.

## Pre-commit

The project uses [prek](https://prek.j178.dev/) with `.pre-commit-config.yaml` to run **go fmt**, **go vet**, and **staticcheck** before each commit.

1. Install [prek](https://prek.j178.dev/installation/) and ensure `staticcheck` is on your PATH (e.g. `go install honnef.co/go/tools/cmd/staticcheck@latest`).
2. Install the git hooks: `prek install -f`
3. Hooks run automatically on `git commit`. To run manually: `prek run` or `prek run --all-files`

The config is compatible with the standard [pre-commit](https://pre-commit.com/) framework; you can use `pre-commit` instead of `prek` if you prefer.

## Tests

```bash
go test ./...
```

## Project layout

- `cmd/gadget-dns-server/` — main entrypoint, config (CLI/env/YAML), server startup
- `internal/config/` — config struct, YAML load, env overlay
- `internal/handler/` — gadget DNS responses and zone apex
- `internal/server/` — UDP, TCP, DoT, DoH, DoQ listeners
- `internal/httpapi/` — HTTP server: `/`, ACME challenge, /healthcheck, /metrics, /feed
- `internal/acme/` — ACME obtain-cert and cert expiry
- `internal/dnssec/` — KSK/ZSK, signer, NSEC, CDS
- `internal/logging/` — JSON slog
- `examples/` — example config and usage
