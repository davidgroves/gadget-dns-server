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

Integration tests against a live server (UDP, TCP, DoT, DoH, DoQ): run `./integration-tests.sh`. The server must already be running. Set `GADGET_DNS_SERVER`, `GADGET_DNS_ZONE`, and optional port env vars (see `./integration-tests.sh --help`). DoQ tests require [doggo](https://github.com/mr-karan/doggo).

## set-cookie (hex value)

RFC 7873 requires the EDNS Cookie option to be 16 bytes (8-byte client + 8-byte server). The value after `set-cookie-` is **hex text** used directly (e.g. 32 hex chars = 16 bytes). For a valid packet use 32 hex characters (e.g. `set-cookie-24a5ac12345678901234567890123456`). Invalid hex (odd length or non-hex) returns NXDOMAIN. **Short valid hex (e.g. `set-cookie-616263`) intentionally emits a malformed packet**—useful for testing validators or clients.

## qname-min

The `*.qname-min.<zone>` endpoint is for QNAME minimization testing (RFC 7816). The canonical test name uses the 5th label `zzzzzzz` (late in the NSEC order). Querying e.g. `a.b.c.d.zzzzzzz.qname-min.<zone>` returns the QNAME received and the sequence of qnames the server saw (oldest first), with the number of requests—e.g. qname-min, then zzzzzzz.qname-min, then d.zzzzzzz.qname-min.

## Deployment

Pushing a tag `v*` runs the Release workflow.