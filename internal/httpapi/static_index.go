package httpapi

// indexHTML is the static instructions page served at /.
const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>gadget-dns-server</title>
	<style>
		body { font-family: system-ui, sans-serif; max-width: 52rem; margin: 0 auto; padding: 1.5rem 2rem; line-height: 1.6; }
		h1 { font-size: 1.5rem; margin-top: 0; }
		h2 { font-size: 1.1rem; margin-top: 1.5rem; }
		code { background: #f0f0f0; padding: 0.15em 0.4em; border-radius: 3px; font-size: 0.9em; }
		pre { background: #f5f5f5; padding: 1rem; overflow-x: auto; border-radius: 4px; }
		ul { margin: 0.5rem 0; padding-left: 1.5rem; }
		a { color: #0066cc; }
	</style>
</head>
<body>
	<h1>gadget-dns-server</h1>
	<p>A DNS server that provides gadget endpoints (myip, myport, counter, random, edns, timestamp, etc.) over UDP, TCP, DoT, DoH, and DoQ, with optional DNSSEC and ACME certificates.</p>

	<h2>Quick start</h2>
	<pre># Build
go build -o gadget-dns-server ./cmd/gadget-dns-server

# Run (replace example.com with your zone)
./gadget-dns-server --domain example.com --udp 127.0.0.1:5353 --tcp 127.0.0.1:5353 --http-port 8080

# Query
dig +short -p 5353 @127.0.0.1 myip.example.com A
dig +short -p 5353 @127.0.0.1 counter.example.com TXT</pre>

	<h2>Gadget endpoints</h2>
	<p>Under your zone, the server answers these names (first label):</p>
	<ul>
		<li><code>myip</code> — A/AAAA: client source IP</li>
		<li><code>myport</code> — TXT: client source port</li>
		<li><code>myaddr</code> — TXT: client address and port</li>
		<li><code>counter</code> — TXT: per-server incrementing counter</li>
		<li><code>random</code> — A/AAAA/TXT: random value</li>
		<li><code>edns</code> — TXT: EDNS options on the request</li>
		<li><code>edns-cs</code>, <code>ecs</code> — TXT: EDNS Client Subnet (raw)</li>
		<li><code>protocol</code> — TXT: transport (UDP, TCP, DoH, DoT, DoQ)</li>
		<li><code>timestamp</code> — TXT: current time (ms), TTL 60</li>
		<li><code>timestamp0</code> — TXT: current time (ms), TTL 0</li>
		<li><code>ttl-N</code> — TXT: current time (s), TTL N seconds (e.g. <code>ttl-60</code>, <code>ttl-0</code>, N up to 86400)</li>
		<li><code>size-N</code> — TXT: response wire size ~N bytes (128–4096, uses EDNS padding)</li>
		<li><code>*.qname-min</code> — TXT: exact QNAME received (for QNAME minimization testing)</li>
		<li><code>sig-fail</code> — A/TXT: intentionally invalid RRSIG; if you resolve it, your resolver is not validating DNSSEC</li>
		<li><code>&lt;token&gt;.diag</code> — query over DNS to record; then open <code>https://&lt;token&gt;.diag.&lt;zone&gt;</code> to view queries</li>
	</ul>

	<h2>Transports</h2>
	<p>Enable with <code>--udp</code>, <code>--tcp</code>, <code>--dot-port 853</code>, <code>--doh-port 443</code>, <code>--doq-port 8853</code>. DoT/DoH/DoQ require <code>--tls-cert</code> and <code>--tls-key</code>.</p>

	<h2>ACME (Let's Encrypt)</h2>
	<pre># Obtain cert once (HTTP server on port 80 must be reachable)
./gadget-dns-server --obtain-cert --acme-domain dns.example.com --tls-cert cert.pem --tls-key key.pem --http-port 80

# Then run server with the cert; renewal runs automatically when configured.</pre>

	<h2>DNSSEC</h2>
	<pre># Generate ALG13 zone keys
./gadget-dns-server --generate-zone-keys --domain example.com --dnssec-ksk ./keys/ksk --dnssec-zsk ./keys/zsk

# Run with DNSSEC
./gadget-dns-server --domain example.com --udp :53 --dnssec --dnssec-ksk ./keys/ksk --dnssec-zsk ./keys/zsk --tls-cert cert.pem --tls-key key.pem</pre>

	<h2>Configuration</h2>
	<p>Precedence: <strong>CLI &gt; environment &gt; YAML</strong>. Use <code>--config path</code> or <code>GADGET_CONFIG</code> for a YAML file. Key options: <code>--domain</code>, <code>--udp</code>, <code>--tcp</code>, <code>--dot-port</code>, <code>--doh-port</code>, <code>--doq-port</code>, <code>--tls-cert</code>, <code>--tls-key</code>, <code>--http-port</code>, <code>--acme-domain</code>, <code>--dnssec</code>, <code>--dnssec-ksk</code>, <code>--dnssec-zsk</code>, <code>--dnssec-rrsig-inception</code>, <code>--dnssec-rrsig-validity</code>.</p>

	<h2>HTTP endpoints (this server)</h2>
	<ul>
		<li><a href="/healthcheck">/healthcheck</a> — liveness</li>
		<li><a href="/metrics">/metrics</a> — Prometheus metrics</li>
		<li><a href="/feed">/feed</a> — NDJSON stream of queries/responses</li>
	</ul>
</body>
</html>
`
