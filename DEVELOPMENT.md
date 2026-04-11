# Development

Notes for people working on gadget-dns-server.

## Pre-commit

The project uses [prek](https://prek.j178.dev/) with `.pre-commit-config.yaml` to run **go fmt**, **go vet**, and **staticcheck** before each commit.

1. Install [prek](https://prek.j178.dev/installation/). The hook runs staticcheck via `go run honnef.co/go/tools/cmd/staticcheck@latest` so it matches `go.mod`’s `toolchain` and you do not need a separate `staticcheck` on PATH (optional: `go install honnef.co/go/tools/cmd/staticcheck@latest` for manual runs).
2. Install the git hooks: `prek install -f`
3. Hooks run automatically on `git commit`. To run manually: `prek run` or `prek run --all-files`

The config is compatible with the standard [pre-commit](https://pre-commit.com/) framework; you can use `pre-commit` instead of `prek` if you prefer.

## Tests

```bash
go test ./...
```

Integration tests against a live server (UDP, TCP, DoT, DoH, DoQ): run `./integration-tests.sh`. The server must already be running. Set `GADGET_DNS_SERVER`, `GADGET_DNS_ZONE`, and optional port env vars (see `./integration-tests.sh --help`). DoQ tests require [doggo](https://github.com/mr-karan/doggo).


## Deployment

Pushing a tag `v*` runs the Release workflow.