# gadget-dns-server

A Go DNS server that combines [dnssrc](https://github.com/davidgroves/dnssrc)-style gadget responses with [dns-sendfile](https://github.com/davidgroves/dns-sendfile)-style transports (UDP, TCP, DoT, DoH, DoQ), ACME certificate acquisition, and optional DNSSEC signing.

## Features

- **Gadget endpoints** (under your zone): `myip`, `myport`, `myaddr`, `counter`, `random`, `edns`, `edns-cs`, `ecs`, `protocol`, `timestamp`, `timestamp0`, `ttl-N` (variable TTL), `size-N` (response size in bytes), `*.qname-min` (QNAME received), `sig-fail` (DNSSEC validation test), `<token>.diag` (diag dashboard)
- **Transports**: UDP, TCP, DNS over TLS (DoT), DNS over HTTPS (DoH), DNS over QUIC (DoQ)
- **ACME**: Obtain Let's Encrypt certificates (HTTP-01) and optional background renewal
- **Single HTTP server** for ACME challenge, `/healthcheck`, `/metrics` (Prometheus), `/feed` (query/response stream)
- **Config**: CLI flags, environment variables (`GADGET_*`), or YAML file
- **DNSSEC**: Optional on-the-fly signing with KSK/ZSK; supports ALG8 (RSASHA256), ALG13 (ECDSAP256SHA256), ALG15 (ED25519); NSEC for denial; CDS for parent

## Build

```bash
go build -o gadget-dns-server ./cmd/gadget-dns-server
```

## Quick start

```bash
# Run on UDP/TCP port 5353 (non-privileged) for zone example.com
./gadget-dns-server --domain example.com --udp 127.0.0.1:5353 --tcp 127.0.0.1:5353 --http-port 8080

# Query
dig +short -p 5353 @127.0.0.1 myip.example.com A
dig +short -p 5353 @127.0.0.1 counter.example.com TXT
```

## DNSSEC

Generate zone keys (ECDSA P-256 by default):

```bash
./gadget-dns-server --generate-zone-keys --domain example.com --dnssec-ksk ./keys/ksk --dnssec-zsk ./keys/zsk
```

Run with DNSSEC signing:

```bash
./gadget-dns-server --domain example.com --udp :53 --dnssec --dnssec-ksk ./keys/ksk --dnssec-zsk ./keys/zsk --tls-cert cert.pem --tls-key key.pem
```

## ACME

Obtain a certificate (HTTP server must be reachable on port 80 for HTTP-01):

```bash
./gadget-dns-server --obtain-cert --acme-domain dns.example.com --tls-cert cert.pem --tls-key key.pem --http-port 80
```

Then run the server with the cert for DoT/DoH/DoQ.

## Configuration

Precedence: **CLI > environment > YAML**.

- `--config path` or `GADGET_CONFIG`: YAML config file
- `--domain` / `GADGET_DOMAIN`: Zone domain (required for server)
- `--udp`, `--tcp`, `--dot-port`, `--doh-port`, `--doq-port`: Listen addresses/ports
- `--tls-cert`, `--tls-key`: TLS certificate and key
- `--http-port`: HTTP server port (ACME, /healthcheck, /metrics, /feed)
- `--acme-domain`: Comma-separated domains for ACME
- `--dnssec`, `--dnssec-ksk`, `--dnssec-zsk`: DNSSEC signing

## HTTP endpoints

- `GET /`: Static instructions page (how to use the app)
- `GET /.well-known/acme-challenge/<token>`: ACME HTTP-01 (used by obtain-cert and renewal)
- `GET /healthcheck`: Returns `{"status":"ok"}`
- `GET /metrics`: Prometheus exposition format
- `GET /feed`: NDJSON stream of query/response events
- `GET https://<token>.diag.<zone>`: Diag dashboard — list of DNS queries recorded for that token (query `<token>.diag.<zone>` over DNS first to record)

