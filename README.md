# gadget-dns-server

A Go based gadget DNS server that is the 3rd evolution of [dnssrc](https://github.com/davidgroves/dnssrc).

Supports UDP, TCP, DoH, DoT, DoH, DoQ, ACME certificate acquisition, and optional DNSSEC signing. 

Some testing features inspired by [whoami.akamai.net](https://whoami.akamai.net) and [nsec3.uk](https://nsec3.uk).

## Features

- **Gadget endpoints** (under your zone): `myip` / `ip`, `myport` / `port`, `myaddr` / `addr`, `connection` / `myconnection` (URL-like: doh://ip:port, dot://[ipv6]:port, etc.), `counter`, `random`, `edns`, `edns-cs`, `ecs`, `protocol`, `timestamp`, `timestamp0`, `ttl-N` (variable TTL), `ednspad-N` (EDNS padding, response size in bytes; A, AAAA, TXT), `size-N` (response size in bytes via random TXT; TXT only), `delay-N` / `delay-X-Y` (response delay in ms), `*.qname-min` (QNAME minimization testing: reports QNAME received and resolver query sequence), DNSSEC fail tests under `dnssec-failed.<zone>` (`sig-fail`, `rrsig-expired`, `rrsig-future`, `nsec-missing`, `nsec-wrong-next`, etc.), TXT display/injection tests under `txt-test.<zone>` (`alert`, `href`, `bobby-tables`), referral test `unresolvable.ns-test.<zone>` (NS to unresolvable names → resolvers should SERVFAIL), `<token>.diag` (diag dashboard). Gadgets also work under diag: `<gadget>.<token>.diag.<zone>` (e.g. `connection.foo.diag.<zone>`) runs the gadget and records the query to the diag dashboard for that token. Set-options (`set-cookie-*`, `set-ede-*`, `set-nsid-*`, `set-noedns`, `set-flags-*`, `set-rcode-*`, `set-status-*`, `set-id-*`, `set-ttl-N`, `set-delay-N` / `set-delay-X-Y`, `set-answer-*`, `set-answer-txt-*`) can be stacked (e.g. `set-cookie-abc.set-ttl-20.<zone>` applies both). **set-noedns** (omit EDNS from the response) takes priority over any other set-option or client request that would add EDNS: when present, the response has no OPT record even if combined with `set-cookie-*`, `set-ede-*`, `set-nsid-*`, or client NSID; `set-ttl-N` sets the TTL of all response RRs to N seconds (0–86400); it does not add records by itself—stack with a gadget or set-answer. **set-delay-N** / **set-delay-X-Y** delay the response by N ms or random X–Y ms (like delay-N but applies to any query) (e.g. `set-ttl-60.counter.<zone>` or `set-ttl-20.set-answer-txt-hello.<zone>`). **set-answer** (A and TXT only): `set-answer-<a>-<b>-<c>-<d>` returns A record(s), `set-answer-txt-<string>` returns TXT; multiple labels add multiple values. For **set-cookie**: the value is hex text (e.g. 32 hex chars = 16 bytes for a valid RFC 7873 cookie); invalid hex returns NXDOMAIN; short hex intentionally emits a malformed packet (for testing).
- **Transports**: UDP, TCP, DNS over TLS (DoT), DNS over HTTPS (DoH), DNS over QUIC (DoQ)
- **ACME**: Obtain Let's Encrypt certificates (HTTP-01) and optional background renewal
- **Single HTTP server** for ACME challenge, `/healthcheck`, `/metrics` (Prometheus), `/feed` (query/response stream)
- **Config**: CLI flags, environment variables (`GADGET_*`), or YAML file. Canonical deployment: delegate the zone to this server (NS at apex), serve apex and `www.<zone>` A/AAAA — see [examples/config.yaml](examples/config.yaml).
- **DNSSEC**: Optional on-the-fly signing with KSK/ZSK; supports ALG8 (RSASHA256), ALG13 (ECDSAP256SHA256), ALG15 (ED25519); NSEC for denial; CDS for parent

## Build

```bash
go build -o gadget-dns-server ./cmd/gadget-dns-server
```

## Quick start

```bash
# Run on UDP/TCP port 5353 (non-privileged) for zone example.com
./gadget-dns-server --domain example.com --udp-port 5353 --tcp-port 5353 --bind 127.0.0.1 --http-port 8080

# Query
dig -p 5353 @127.0.0.1 myip.example.com A
dig -p 5353 @127.0.0.1 counter.example.com TXT
```

## DNSSEC

Generate zone keys (ECDSA P-256 by default):

```bash
./gadget-dns-server --generate-zone-keys --domain example.com --dnssec-ksk ./keys/ksk --dnssec-zsk ./keys/zsk
```

Run with DNSSEC signing:

```bash
./gadget-dns-server --domain example.com --udp-port 53 --tcp-port 53 --dnssec --dnssec-ksk ./keys/ksk --dnssec-zsk ./keys/zsk --tls-cert cert.pem --tls-key key.pem
```

**DNSSEC fail tests:** With DNSSEC enabled, the server exposes names under `dnssec-failed.<zone>` that deliberately break validation (e.g. `sig-fail.dnssec-failed.<zone>`, `rrsig-expired.dnssec-failed.<zone>`). You should get SERVFAIL or no answer when validation is on. Query with a validating resolver or use [dnsviz](https://github.com/dnsviz/dnsviz) to confirm bogus reasons.

## ACME

Obtain a certificate (HTTP server must be reachable on port 80 for HTTP-01). For the canonical setup (zone delegated to this server, webserver at www), request certs for `www.<zone>` and `diag.<zone>` — see [examples/config.yaml](examples/config.yaml).

```bash
./gadget-dns-server --obtain-cert --acme-domain www.example.com --acme-domain diag.example.com --tls-cert cert.pem --tls-key key.pem --http-port 80
```

Then run the server with the cert for DoT/DoH/DoQ.

## DoQ (DNS over QUIC)

If you enable DoQ and see a log line like `failed to sufficiently increase receive buffer size (was: … kiB, wanted: 2048 kiB, got: … kiB)`, raise the kernel’s UDP buffer limits (once per boot, or persist via `/etc/sysctl.d/`):

```bash
sudo sysctl -w net.core.rmem_max=2500000
sudo sysctl -w net.core.wmem_max=2500000
```

To make these persistent (e.g. on Linux), add the same lines to a file under `/etc/sysctl.d/` and run `sudo sysctl -p` or reboot.

**Testing DoQ:** `dig` does not support DNS over QUIC. Use **[doggo](https://github.com/mr-karan/doggo)** (a dig-like CLI with DoQ support). Install: `go install github.com/mr-karan/doggo/cmd/doggo@latest` or `brew install doggo`. Query directly at your server (default DoQ port 8853):

```bash
doggo TXT connection.dnssrc.example.com @quic://dnssrc.example.com:8853
```

The response will show <code>doq://…</code>, confirming the query used QUIC.

## DoT and DoH with dig

You need a **modern dig** (BIND 9.17+ for `+https`, BIND 9.19+ for `+tls`). Query **directly at the server** (use `@your-server`), not via a recursive resolver. Use the <strong>connection</strong> gadget so the TXT response shows the transport in use (<code>dot://…</code> or <code>doh://…</code>).

**DoT (port 853):**

```bash
dig +tls @dnssrc.example.com connection.dnssrc.example.com TXT
```

**DoH (port 443, path `/dns-query`):**

```bash
dig +https @dnssrc.example.com connection.dnssrc.example.com TXT
```

Replace `dnssrc.example.com` with your server’s hostname (the one in your TLS certificate). DoT uses port 853 by default; DoH uses HTTPS on port 443.

**Recursive–to–authority security:** Today, stub→recursive and recursive→authority are often unencrypted. The [DELEG (Extensible Delegation for DNS)](https://datatracker.ietf.org/doc/draft-ietf-deleg/) internet draft aims to allow delegation records to carry server capabilities (e.g. DoT/DoH), so recursive resolvers can securely reach authoritative servers in the future.

## Configuration

Precedence: **CLI > environment > YAML**.

- `--config path` or `GADGET_CONFIG`: YAML config file
- `--domain` / `GADGET_DOMAIN`: Zone domain (required for server)
- `--udp-port`, `--tcp-port`, `--dot-port`, `--doh-port`, `--doq-port`: Listen ports; `--bind`: comma-separated bind addresses (omit = all interfaces)
- `--tls-cert`, `--tls-key`: TLS certificate and key
- `--http-port`: HTTP server port (ACME, /healthcheck, /metrics, /feed)
- `--acme-domain`: Comma-separated domains for ACME
- `--dnssec`, `--dnssec-ksk`, `--dnssec-zsk`: DNSSEC signing
- `GADGET_SERVER_IPS` or `server_ips`: Optional. IPs for zone apex, `www.<zone>`, and diag. If unset, derived from **binds** (when specific IPs) or from **interface addresses** (when binding to 0.0.0.0/::).
- `GADGET_DIAG_RETENTION` or `diag_retention`: How long to keep diagnostic (token.diag) data; e.g. `15m`, `1h`. Default 15m. Data older than this is pruned.

## HTTP endpoints

- `GET /`: Static instructions page (how to use the app)
- `GET /.well-known/acme-challenge/<token>`: ACME HTTP-01 (used by obtain-cert and renewal)
- `GET /healthcheck`: Returns `{"status":"ok"}`
- `GET /metrics`: Prometheus exposition format
- `GET /feed`: NDJSON stream of query/response events
- `GET https://diag.<zone>/<token>`: Diag dashboard — list of DNS queries recorded for that token (query `<token>.diag.<zone>` over DNS first to record). Diagnostic data is kept for the period set by **diag_retention** (default 15m); older data is pruned.

For the diag dashboard over HTTPS: (1) apex/www/diag need A/AAAA — use **server_ips**, or bind to specific IPs, or bind to 0.0.0.0/:: (then interface IPs are used); (2) add `diag.<zone>` to **acme_domains** for the cert.

# Full startup guide.

I recommend running the domain insecure first. Then adding DS records to the parent based on the CDS records.

You NEED the server running to serve the DNS records that the ACME / LetsEncrypt system needs to get your SSL cert, so if you don't do this in the correct order you have a chicken and egg problem.

```
$ mkdir keys
$ mkdir certs
# Obtain SSL certs.
$ bin/gadget-dns-server --obtain-cert
# Setup DNSSEC keys.
$ bin/gadget-dns-server --generate-zone-keys --domain <your_domain> --dnssec-ksk keys/ksk --dnssec-zsk keys/zsk
$ bin/gadget-dms-server
```

