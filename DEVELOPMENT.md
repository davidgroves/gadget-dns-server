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

## Deployment

Pushing a tag `v*` runs the Release workflow: build, release, then deploy to `dnssrc.fibrecat.org`.

**Required:** Add your SSH private key as a repo secret:

```bash
gh secret set DEPLOY_SSH_KEY --repo owner/gadget-dns-server < /path/to/deploy_key
```

**On the server:** Put the matching public key in the deploy user’s `~/.ssh/authorized_keys`. The deploy user must be able to run (e.g. via sudoers) without a password:

- `sudo mv ~/gadget-dns-server.new /home/gadget-dns/bin/gadget-dns-server`
- `sudo chmod +x /home/gadget-dns/bin/gadget-dns-server`
- `sudo setcap "cap_net_bind_service=+ep" /home/gadget-dns/bin/gadget-dns-server`
- `sudo -u gadget-dns env XDG_RUNTIME_DIR=/run/user/$(id -u gadget-dns) systemctl --user restart gadget-dns-server`

**Optional repo variables** (Settings → Secrets and variables → Actions → Variables):

- `DEPLOY_USER` — SSH user (default: `deploy`)
- `DEPLOY_ARCH` — `linux/amd64` or `linux/arm64` (default: `linux/amd64`)
