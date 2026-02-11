package httpapi

// indexZonePlaceholder is replaced with the configured domain when serving the index.
const indexZonePlaceholder = "__ZONE__"

// indexVersionPlaceholder is replaced with the app version when serving the index.
const indexVersionPlaceholder = "__VERSION__"

// indexHTML is the static instructions page served at /. End-user only: how to query each gadget.
// __ZONE__ is replaced with the zone (domain from config) when serving.
const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Gadget DNS — usage</title>
	<script defer src="https://unpkg.com/alpinejs@3.13.3/dist/cdn.min.js"></script>
	<style>
		:root { --bg: #0f0f14; --surface: #18181f; --border: #2d2d3a; --text: #e4e4e7; --text-muted: #a1a1aa; --accent: #818cf8; --accent-hover: #6366f1; }
		html { font-size: 1.0625rem; }
		body { font-family: system-ui, -apple-system, sans-serif; max-width: 52rem; margin: 0 auto; padding: 1.5rem 2rem; line-height: 1.6; background: var(--bg); color: var(--text); min-height: 100vh; }
		h1 { font-size: 1.5rem; margin-top: 0; font-weight: 600; }
		h1 .version { font-size: 0.85rem; font-weight: 500; color: var(--text-muted); }
		h2 { font-size: 1.1rem; margin-top: 1.5rem; font-weight: 600; color: var(--text); }
		a { color: var(--accent); text-decoration: none; }
		a:hover { text-decoration: underline; }
		code { background: var(--surface); color: var(--accent); padding: 0.2em 0.45em; border-radius: 4px; font-size: 0.9em; border: 1px solid var(--border); }
		pre { background: var(--surface); padding: 1rem; overflow-x: auto; border-radius: 6px; font-size: 0.88em; border: 1px solid var(--border); color: var(--text-muted); }
		.endpoint { margin-bottom: 1.25rem; padding: 1rem; border-radius: 6px; border: 1px solid var(--border); background: var(--surface); }
		.endpoint p { margin: 0.25rem 0 0.5rem 0; color: var(--text-muted); }
		.note { background: var(--surface); padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1.5rem; font-size: 0.95em; border-left: 3px solid var(--accent); color: var(--text-muted); }
		.pre-wrap { position: relative; margin-bottom: 0.5rem; }
		.pre-wrap:last-child { margin-bottom: 0; }
		.pre-wrap .copy-btn { position: absolute; top: 0.5rem; right: 0.5rem; background: var(--accent); color: #fff; border: none; padding: 0.25rem 0.5rem; border-radius: 4px; cursor: pointer; font-size: 0.8rem; }
		.pre-wrap .copy-btn:hover { background: var(--accent-hover); }
		.type-badge { display: inline-block; margin-left: 0.35rem; padding: 0.1em 0.4em; font-size: 0.75rem; font-weight: 500; background: var(--border); color: var(--text-muted); border-radius: 4px; }
		.set-options-group { margin-bottom: 1.25rem; padding: 1rem; border-radius: 6px; border: 1px solid var(--border); background: #1a1a24; }
		.set-options-group .endpoint { background: #1a1a24; margin-bottom: 1rem; }
		.set-options-group .endpoint:last-child { margin-bottom: 0; }
	</style>
</head>
<body>
	<script>var GADGET_ZONE = '__ZONE__';</script>
	<h1>Gadget DNS <span class="version">__VERSION__</span></h1>
	<p>This server answers DNS queries for gadget names under zone <code>__ZONE__</code>. Each name returns a specific value (your IP, a counter, time, etc.). Copy and paste the <code>dig</code> commands below.</p>
	<div class="note">Some testing features inspired by <a href="https://whoami.akamai.net" target="_blank" rel="noopener">whoami.akamai.net</a> and <a href="https://nsec3.uk/" target="_blank" rel="noopener">nsec3.uk</a>.</div>
	<div class="note"><strong>Tip:</strong> Use <code>dig @__ZONE__ …</code> to query this server directly, or use your normal resolver so it forwards to this server. Shift+click Copy to paste commands with <code>@__ZONE__</code> already in each line.</div>
	<div class="note">Want to run your own instance? Use this project: <a href="https://github.com/davidgroves/gadget-dns-server" target="_blank" rel="noopener">github.com/davidgroves/gadget-dns-server</a>.</div>

	<div class="endpoint">
		<h2>help <span class="type-badge">TXT</span></h2>
		<p>TXT record with a link to this docs page (<code>https://www.__ZONE__</code>).</p>
		<pre>dig help.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>myip / ip <span class="type-badge">A</span> <span class="type-badge">AAAA</span> <span class="type-badge">TXT</span></h2>
		<p>Your client's IP address. <strong>Recommend using TXT</strong> so you always get the real address. A/AAAA return both record types for DNSSEC; if the packet came via IPv6, A is <code>0.0.0.0</code> (placeholder), and if via IPv4, AAAA is <code>::</code> (placeholder).</p>
		<pre>dig myip.__ZONE__ TXT</pre>
		<pre>dig ip.__ZONE__ TXT</pre>
		<pre>dig myip.__ZONE__ A</pre>
		<pre>dig myip.__ZONE__ AAAA</pre>
	</div>

	<div class="endpoint">
		<h2>myport / port <span class="type-badge">TXT</span></h2>
		<p>Your client's source port (TXT).</p>
		<pre>dig myport.__ZONE__ TXT</pre>
		<pre>dig port.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>myaddr / addr <span class="type-badge">TXT</span></h2>
		<p>Your client's address and port (TXT, two strings).</p>
		<pre>dig myaddr.__ZONE__ TXT</pre>
		<pre>dig addr.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>connection / myconnection <span class="type-badge">TXT</span></h2>
		<p>URL-like representation of how the client connected (TXT): <code>doh://&lt;ip4&gt;:&lt;port&gt;</code>, <code>dot://[&lt;ipv6&gt;]:&lt;port&gt;</code>, <code>doq://</code>, <code>udp://</code>, or <code>tcp://</code>.</p>
		<pre>dig connection.__ZONE__ TXT</pre>
		<pre>dig myconnection.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>counter <span class="type-badge">TXT</span></h2>
		<p>Per-server incrementing counter (TXT).</p>
		<pre>dig counter.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>random <span class="type-badge">A</span> <span class="type-badge">AAAA</span> <span class="type-badge">TXT</span></h2>
		<p>Random value (A, AAAA, or TXT).</p>
		<pre>dig random.__ZONE__ A</pre>
		<pre>dig random.__ZONE__ AAAA</pre>
		<pre>dig random.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>protocol <span class="type-badge">TXT</span></h2>
		<p>Transport used: UDP, TCP, DoT, DoH, or DoQ (TXT).</p>
		<pre>dig protocol.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>timestamp-N <span class="type-badge">TXT</span></h2>
		<p>Current time in milliseconds (TXT), with TTL = N seconds (0–86400). Example: <code>timestamp-60</code>, <code>timestamp-0</code>.</p>
		<pre>dig timestamp-60.__ZONE__ TXT</pre>
		<pre>dig timestamp-0.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>ttl-N <span class="type-badge">TXT</span></h2>
		<p>Current Unix time in seconds, with TTL = N (0–86400). Example: <code>ttl-60</code>, <code>ttl-0</code>.</p>
		<pre>dig ttl-60.__ZONE__ TXT</pre>
		<pre>dig ttl-0.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>edns <span class="type-badge">TXT</span></h2>
		<p>EDNS options present on the request (TXT).</p>
		<pre>dig edns.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>edns-cs / ecs</h2>
		<p>EDNS Client Subnet from the request (TXT).</p>
		<pre>dig edns-cs.__ZONE__ TXT</pre>
		<pre>dig ecs.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>cookie <span class="type-badge">TXT</span></h2>
		<p>EDNS Cookie (RFC 7873) from the request, echoed as TXT. Use <code>+cookie</code> with dig to send a cookie.</p>
		<pre>dig +cookie cookie.__ZONE__ TXT</pre>
	</div>

	<div class="set-options-group">
	<div class="endpoint">
		<h2>Stacking set-options <span class="type-badge">TXT</span></h2>
		<p>You can combine multiple set-options in one query by listing them left to right. All apply: e.g. <code>set-cookie-*</code> (hex value), <code>set-ede-*</code>, <code>set-nsid-*</code>, <code>set-noedns</code>, <code>set-flags-*</code>, <code>set-rcode-*</code>, <code>set-status-*</code>, <code>set-id-*</code>, <code>set-ttl-N</code>, <code>set-delay-*</code>, <code>set-answer-*</code>. Example: <code>set-cookie-616263.set-ttl-20.counter.__ZONE__</code> sets the EDNS cookie (hex 616263), the response TTL to 20, and returns the counter gadget. <strong>Exception:</strong> <code>set-noedns</code> always wins—when present, the response will have no OPT record even if other set-options (e.g. <code>set-cookie-*</code>, <code>set-nsid-*</code>) or client NSID would normally add EDNS.</p>
		<pre>dig set-ttl-60.counter.__ZONE__ TXT</pre>
		<pre>dig set-rcode-3.set-id-0x1234.__ZONE__ TXT</pre>
		<pre>dig set-cookie-78797a.set-ede-5-foo.mytoken.diag.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>set-cookie-&lt;string&gt; <span class="type-badge">TXT</span></h2>
		<p>Force the response to include an EDNS Cookie option with the given value (e.g. return a cookie when the client did not send one, or override the cookie). The string is hex-encoded; for a valid packet the cookie must be <strong>16 bytes</strong> (RFC 7873: 8-byte client + 8-byte server), so use a 16-character string (e.g. <code>set-cookie-1234567890123456</code>). <strong>Setting a short cookie (e.g. <code>set-cookie-abc</code>) intentionally emits a malformed packet</strong>—useful for testing.</p>
		<pre>dig set-cookie-1234567890123456.__ZONE__ TXT</pre>
		<pre>dig +cookie set-cookie-24a5ac1234567890.__ZONE__ TXT</pre>
		<p><em>Note:</em> <code>set-cookie-abc</code> is valid as a label but produces a malformed EDNS cookie (3 bytes); use only when testing malformed responses.</p>
	</div>

	<div class="endpoint">
		<h2>set-ede-&lt;number&gt;-&lt;string&gt; <span class="type-badge">TXT</span></h2>
		<p>Force the response to include an Extended DNS Error (RFC 8914) option with the given code and optional text, even when the response is otherwise successful.</p>
		<pre>dig set-ede-5.__ZONE__ TXT</pre>
		<pre>dig set-ede-5-test.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>set-nsid-&lt;string&gt; <span class="type-badge">TXT</span></h2>
		<p>Force the response to include an EDNS NSID (Name Server Identifier, RFC 5001) option with the given string. When the client sends an NSID option (e.g. <code>dig +nsid</code>), the server returns NSID by default using the same value as <code>hostname.bind</code> (CH class). Use <code>set-nsid-*</code> to override that with a custom identifier (e.g. <code>set-nsid-my-server-1</code>). The value is the literal string after the prefix (hyphens allowed).</p>
		<pre>dig +nsid set-nsid-my-server.__ZONE__ TXT</pre>
		<pre>dig +nsid __ZONE__ SOA</pre>
	</div>

	<div class="endpoint">
		<h2>set-noedns <span class="type-badge">TXT</span></h2>
		<p>Omit EDNS from the response: do not include an OPT record even when the client sent EDNS. Useful for testing clients that must handle non-EDNS responses.</p>
		<p><strong>Priority:</strong> <code>set-noedns</code> takes priority over any other set-option or behavior that would add EDNS to the response. When <code>set-noedns</code> is combined with <code>set-cookie-*</code>, <code>set-ede-*</code>, <code>set-nsid-*</code>, or when the client sends an NSID option (e.g. <code>dig +nsid</code>), the response will still have <strong>no OPT record</strong>.</p>
		<pre>dig set-noedns.__ZONE__ TXT</pre>
		<pre>dig set-noedns.myip.__ZONE__ A</pre>
		<pre>dig set-noedns.set-cookie-616263.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>set-flags-&lt;bitmask&gt; <span class="type-badge">TXT</span></h2>
		<p>Set the DNS response header flags to the given 16-bit value. Accepts binary (e.g. <code>100010100</code>), decimal (e.g. <code>23</code>), or hex with <code>0x</code> prefix (e.g. <code>0x3c</code>). The low 4 bits set the RCODE; higher bits set QR, Opcode, AA, TC, RD, RA, Z, AD, CD (see RFC 1035 / 4035).</p>
		<p><strong>Examples:</strong></p>
		<ul style="margin:0.25rem 0 0.5rem 0; padding-left:1.25rem; color:var(--text-muted);">
			<li><code>set-flags-0x8180</code> — response (QR) + Recursion Available (RA)</li>
			<li><code>set-flags-0x8580</code> — response + Authoritative (AA) + RA</li>
			<li><code>set-flags-23</code> — Checking Disabled (CD) + RCODE 7 (REFUSED)</li>
			<li><code>set-flags-0x0200</code> — Truncated (TC), e.g. for testing UDP fallback</li>
		</ul>
		<pre>dig set-flags-0x8180.__ZONE__ TXT</pre>
		<pre>dig set-flags-0x8580.__ZONE__ TXT</pre>
		<pre>dig set-flags-23.__ZONE__ TXT</pre>
		<pre>dig set-flags-0x0200.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>set-rcode-&lt;value&gt; / set-status-&lt;value&gt; <span class="type-badge">TXT</span></h2>
		<p>Set the DNS response RCODE (status code). Accepts decimal (0–15 or extended), hex with <code>0x</code> prefix, or RCODE name (e.g. <code>NOERROR</code>, <code>NXDOMAIN</code>, <code>SERVFAIL</code>, <code>REFUSED</code>). <code>set-status-</code> is an alias for <code>set-rcode-</code>.</p>
		<pre>dig set-rcode-3.__ZONE__ TXT</pre>
		<pre>dig set-status-NXDOMAIN.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>set-id-&lt;value&gt; <span class="type-badge">TXT</span></h2>
		<p>Set the DNS response transaction ID (16-bit). Accepts decimal (0–65535) or hex with <code>0x</code> prefix.</p>
		<pre>dig set-id-12345.__ZONE__ TXT</pre>
		<pre>dig set-id-0xabcd.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>set-ttl-&lt;N&gt;</h2>
		<p>Set the TTL of all response RRs (Answer and Authority) to N seconds (0–86400). Useful for testing TTL behavior. <strong>set-ttl only modifies the TTL of whatever would be returned</strong>—it does not add records by itself. Stack it with a gadget or set-answer to get an answer with the desired TTL, e.g. <code>set-ttl-60.counter.__ZONE__</code> or <code>set-ttl-20.set-answer-txt-hello.__ZONE__</code>.</p>
		<pre>dig set-ttl-60.counter.__ZONE__ TXT</pre>
		<pre>dig set-ttl-20.set-answer-txt-hello.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>set-delay-N / set-delay-X-Y</h2>
		<p>Delay the response by N milliseconds, or by a random number of milliseconds between X and Y (inclusive). Works like <code>delay-N</code> / <code>delay-X-Y</code>, but as a set-option it applies to <strong>any</strong> query—stack it with a gadget or other set-options to delay whatever would be returned. Example: <code>set-delay-100.counter.__ZONE__</code> returns the counter after 100 ms; <code>set-delay-50-200.myip.__ZONE__</code> returns your IP after a random delay between 50 and 200 ms. Max delay 300000 ms (5 minutes).</p>
		<pre>dig set-delay-0.counter.__ZONE__ TXT</pre>
		<pre>dig set-delay-100.myip.__ZONE__ TXT</pre>
		<pre>dig set-delay-50-200.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>set-answer-&lt;value&gt; (A and TXT only) <span class="type-badge">A</span> <span class="type-badge">TXT</span></h2>
		<p>Override the response Answer section with the given values. <strong>Only A and TXT record types are supported.</strong> You can stack multiple values; each <code>set-answer-*</code> label adds one value.</p>
		<p><strong>A records:</strong> <code>set-answer-&lt;a&gt;-&lt;b&gt;-&lt;c&gt;-&lt;d&gt;</code> — four hyphen-separated octets (0–255), e.g. <code>set-answer-1-2-3-4</code> returns A record <code>1.2.3.4</code>. Multiple labels return multiple A records.</p>
		<p><strong>TXT records:</strong> <code>set-answer-txt-&lt;string&gt;</code> — the rest of the label is the TXT string (hyphens allowed). Multiple <code>set-answer-txt-*</code> labels produce one TXT RR with multiple strings.</p>
		<pre>dig set-answer-1-2-3-4.set-answer-5-6-7-8.__ZONE__ A</pre>
		<pre>dig set-answer-txt-hello.set-answer-txt-world.__ZONE__ TXT</pre>
		<pre>dig set-answer-1-2-3-4.set-answer-5-6-7-8.foo.diag.__ZONE__ A</pre>
	</div>
	</div>

	<div class="endpoint">
		<h2>ednspad-N <span class="type-badge">A / AAAA / TXT</span></h2>
		<p>Response wire size approximately N bytes (128–4096). Uses EDNS padding on all record types.</p>
		<pre>dig ednspad-256.__ZONE__ A</pre>
		<pre>dig ednspad-256.__ZONE__ AAAA</pre>
		<pre>dig ednspad-256.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>size-N <span class="type-badge">TXT</span></h2>
		<p>Response wire size approximately N bytes (128–4096). Returns random TXT content to reach the requested size. TXT only.</p>
		<pre>dig size-256.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>delay-N / delay-X-Y <span class="type-badge">TXT</span></h2>
		<p>Gadget that delays the response by N milliseconds, or by a random number of milliseconds between X and Y (inclusive). Returns a TXT record (e.g. <code>delayed 100ms</code>). Useful for timeout and latency testing. For delaying <strong>any</strong> query (e.g. counter, myip), use the set-option <code>set-delay-N</code> or <code>set-delay-X-Y</code> instead. Example: <code>delay-500</code>, <code>delay-100-500</code>.</p>
		<pre>dig delay-500.__ZONE__ TXT</pre>
		<pre>dig delay-100-500.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>qname-min <span class="type-badge">TXT</span></h2>
		<p>QNAME minimization testing (<a href="https://datatracker.ietf.org/doc/html/rfc7816" target="_blank" rel="noopener">RFC 7816</a>). Query any name under <code>*.qname-min.__ZONE__</code> (e.g. <code>a.b.c.d.qname-min.__ZONE__</code>). The TXT response includes the QNAME received and the sequence of qnames the server saw from that resolver (oldest first). Because all names are in the same zone on this server, the full sequence is visible.</p>
		<p><strong>With QNAME minimization:</strong> For <code>a.b.c.d.__ZONE__</code> you <strong>should</strong> see 2 queries: first <code>qname-min.__ZONE__</code> (or <code>__ZONE__</code>), then <code>a.b.c.d.qname-min.__ZONE__</code>. The resolver discovers there is no delegation and then sends the full name.</p>
		<p><strong>Other outcomes:</strong></p>
		<ol style="margin:0.25rem 0 0.5rem 0; padding-left:1.5rem; color:var(--text-muted);">
			<li><strong>Whole name straight away</strong> — one query for <code>a.b.c.d.qname-min.__ZONE__</code>; indicates no QNAME minimization.</li>
			<li><strong>Buggy minimization</strong> — queries for <code>qname-min.__ZONE__</code>, then <code>d.qname-min.__ZONE__</code>, then <code>c.d.qname-min.__ZONE__</code>, etc.; the resolver keeps adding one label at a time instead of jumping to the full name after a non-referral.</li>
		</ol>
		<p><strong>Why 2 queries is expected:</strong></p>
		<ul style="margin:0.25rem 0 0.5rem 0; padding-left:1.5rem; color:var(--text-muted);">
			<li><strong>The Referral (Standard):</strong> If the server for the zone returns a referral (an NS record in the Authority section pointing to the same or another server), the resolver proceeds to the next label—e.g. after <code>qname-min.__ZONE__</code> it might ask for <code>d.qname-min.__ZONE__</code>, then <code>c.d.qname-min.__ZONE__</code>.</li>
			<li><strong>The &quot;No Data&quot; response:</strong> If the server responds with RCODE 0 (NoError) but no NS records for the subdomain—meaning subdomains are just records in the same zone—the resolver learns there is no further delegation.</li>
			<li><strong>The Shortcut (<a href="https://datatracker.ietf.org/doc/html/rfc9156" target="_blank" rel="noopener">RFC 9156</a>):</strong> If the resolver receives a response that is not a referral (i.e. an answer or a Name Error), it may stop minimizing and send the full remaining query. So after one minimal query, it can send <code>a.b.c.d.qname-min.__ZONE__</code> directly.</li>
		</ul>
		<pre>dig zzzzzzz.qname-min.__ZONE__ TXT</pre>
		<pre>dig a.b.c.d.qname-min.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>txt-test (display / injection testing) <span class="type-badge">TXT</span></h2>
		<p>Fixed TXT records under <code>txt-test.__ZONE__</code> for testing how resolvers, tools, or UIs display or escape TXT data. Use to check for XSS, link injection, or SQL-injection-style payload handling.</p>
		<ul style="margin:0.25rem 0 0.5rem 0; padding-left:1.25rem; color:var(--text-muted);">
			<li><code>alert.txt-test.__ZONE__</code> — TXT containing <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></li>
			<li><code>href.txt-test.__ZONE__</code> — TXT containing <code>https://example.com/</code></li>
			<li><code>bobby-tables.txt-test.__ZONE__</code> — TXT containing <code>' OR '1'='1</code></li>
		</ul>
		<pre>dig alert.txt-test.__ZONE__ TXT</pre>
		<pre>dig href.txt-test.__ZONE__ TXT</pre>
		<pre>dig bobby-tables.txt-test.__ZONE__ TXT</pre>
	</div>

	<div class="endpoint">
		<h2>ns-test (referral testing)</h2>
		<p><code>unresolvable.ns-test.__ZONE__</code> returns a referral (NS records in Authority) pointing to names this server does not serve (no A/AAAA glue). A recursive resolver that follows the delegation will try to resolve those NS targets and should eventually get NXDOMAIN or timeout, leading to SERVFAIL. Use to test how resolvers handle broken delegations.</p>
		<pre>dig unresolvable.ns-test.__ZONE__ A</pre>
	</div>

	<div class="endpoint">
		<h2>DNSSEC fail tests (dnssec-failed subdomain)</h2>
		<p>These names deliberately break DNSSEC so you can check that your resolver validates (you should get SERVFAIL or no answer when validation is on). All fail-case names live under <code>dnssec-failed.__ZONE__</code>.</p>
		<ul style="margin:0.25rem 0 0.5rem 0; padding-left:1.25rem; color:var(--text-muted);">
			<li><code>sig-fail.dnssec-failed.__ZONE__</code> — invalid RRSIG (corrupted signature)</li>
			<li><code>rrsig-expired.dnssec-failed.__ZONE__</code> — RRSIG validity in the past (expired)</li>
			<li><code>rrsig-future.dnssec-failed.__ZONE__</code> — RRSIG validity in the future (not yet valid)</li>
			<li><code>nsec-missing.dnssec-failed.__ZONE__</code> — NODATA without NSEC</li>
			<li><code>nsec-wrong-next.dnssec-failed.__ZONE__</code> — NSEC with wrong NextDomain (chain broken)</li>
			<li><code>rrsig-wrong-alg.dnssec-failed.__ZONE__</code> — RRSIG claims wrong algorithm</li>
			<li><code>rrsig-wrong-rrset.dnssec-failed.__ZONE__</code> — RRSIG signed over wrong RRset</li>
			<li><code>rrsig-missing.dnssec-failed.__ZONE__</code> — RRset with no RRSIG</li>
			<li><code>nsec3-instead.dnssec-failed.__ZONE__</code> — NSEC3 in response (zone is NSEC-only)</li>
		</ul>
		<pre>dig sig-fail.dnssec-failed.__ZONE__ A</pre>
		<pre>dig rrsig-expired.dnssec-failed.__ZONE__ A</pre>
		<pre>dig nsec-missing.dnssec-failed.__ZONE__ A</pre>
	</div>

	<div class="endpoint">
		<h2>entropy</h2>
		<p>Port and transaction ID entropy check. The browser triggers DNS lookups; results show source port and ID randomness (GREAT/GOOD/POOR).</p>
		<p>Open <a href="/entropy">/entropy</a> to run the check.</p>
	</div>

	<div class="endpoint">
		<h2>DoT and DoH with dig</h2>
		<p>You need a <strong>modern dig</strong> (BIND 9.17+ for <code>+https</code>, BIND 9.19+ for <code>+tls</code>). Query <strong>directly at this server</strong> (<code>@__ZONE__</code>), not via a recursive resolver.</p>
		<p>Use the <strong>connection</strong> gadget so the TXT response shows the transport in use (<code>dot://…</code>, <code>doh://…</code>, or <code>doq://…</code>).</p>
		<p><strong>DoT (port 853):</strong></p>
		<pre>dig +tls @__ZONE__ connection.__ZONE__ TXT</pre>
		<p><strong>DoH (port 443, path /dns-query):</strong></p>
		<pre>dig +https @__ZONE__ connection.__ZONE__ TXT</pre>
		<p><strong>DoQ (port 8853):</strong> <code>dig</code> doesn't support DNS over QUIC. Use the <a href="https://github.com/mr-karan/doggo" target="_blank" rel="noopener">doggo</a> client (install: <code>go install github.com/mr-karan/doggo/cmd/doggo@latest</code> or <code>brew install doggo</code>). Query directly at this server; the response will show <code>doq://…</code>.</p>
		<pre>doggo TXT connection.__ZONE__ @quic://__ZONE__:8853</pre>
		<p class="note" style="margin-top:0.75rem;margin-bottom:0;"><strong>Recursive–to–authority security:</strong> Today, stub→recursive and recursive→authority are often unencrypted. The <a href="https://datatracker.ietf.org/doc/draft-ietf-deleg/" target="_blank" rel="noopener">DELEG (Extensible Delegation for DNS)</a> internet draft aims to allow delegation records to carry server capabilities (e.g. DoT/DoH), so recursive resolvers can securely reach authoritative servers in the future.</p>
	</div>

	<!-- Keep diag at the bottom: add new endpoints above this comment. -->
	<div class="endpoint">
		<h2>token.diag and gadget.token.diag <span class="type-badge">TXT</span></h2>
		<p>Record a query for a token, then open the dashboard in a browser. Replace <code>mytoken</code> with any label.</p>
		<pre>dig mytoken.diag.__ZONE__ TXT</pre>
		<p>Then open <a href="https://diag.__ZONE__/">https://diag.__ZONE__/</a> to enter your token, or go directly to <code>https://diag.__ZONE__/&lt;token&gt;</code> to view recorded queries for that token.</p>
		<p>You can also run a gadget under diag: <code>&lt;gadget&gt;.&lt;token&gt;.diag.__ZONE__</code> returns the gadget response (e.g. connection URL, myip) and still records the query to the diag dashboard for that token. Example: <code>connection.foo.diag.__ZONE__</code> returns the connection URL and records under token <code>foo</code>.</p>
		<pre>dig connection.foo.diag.__ZONE__ TXT</pre>
		<pre>dig myip.mytoken.diag.__ZONE__ TXT</pre>
	</div>
	<script>
	document.querySelectorAll('.endpoint pre').forEach(function(pre) {
		var wrap = document.createElement('div');
		wrap.className = 'pre-wrap';
		pre.parentNode.insertBefore(wrap, pre);
		wrap.appendChild(pre);
		var btn = document.createElement('button');
		btn.type = 'button';
		btn.className = 'copy-btn';
		btn.textContent = 'Copy';
		btn.title = 'Copy. Shift+click to copy with @server in every command.';
		btn.onclick = function(e) {
			var text = pre.textContent.trim();
			if (e.shiftKey && typeof GADGET_ZONE === 'string') {
				text = text.split('\n').map(function(line) {
					return line.replace(/^dig /, 'dig @' + GADGET_ZONE + ' ');
				}).join('\n');
			}
			navigator.clipboard.writeText(text).then(function() {
				btn.textContent = 'Copied!';
				setTimeout(function() { btn.textContent = 'Copy'; }, 2000);
			});
		};
		wrap.appendChild(btn);
	});
	</script>
</body>
</html>
`

// diagTokenPromptHTML is the page at /mytoken/ on the diag host: message + token input. __ZONE__ replaced when serving.
const diagTokenPromptHTML = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Diag — enter token</title>
	<script defer src="https://unpkg.com/alpinejs@3.13.3/dist/cdn.min.js"></script>
	<style>
		:root { --bg: #0f0f14; --surface: #18181f; --border: #2d2d3a; --text: #e4e4e7; --text-muted: #a1a1aa; --accent: #818cf8; --accent-hover: #6366f1; }
		html { font-size: 1.0625rem; }
		body { font-family: system-ui, -apple-system, sans-serif; max-width: 32rem; margin: 0 auto; padding: 2rem; line-height: 1.6; background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; justify-content: center; }
		h1 { font-size: 1.35rem; margin-top: 0; font-weight: 600; }
		p { color: var(--text-muted); margin: 0.5rem 0 1rem 0; }
		.form-row { display: flex; gap: 0.5rem; margin-top: 1rem; }
		input[type="text"] { flex: 1; background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 0.6rem 0.75rem; border-radius: 6px; font-size: 1rem; }
		input[type="text"]::placeholder { color: var(--text-muted); }
		input[type="text"]:focus { outline: none; border-color: var(--accent); }
		button { background: var(--accent); color: #fff; border: none; padding: 0.6rem 1.25rem; border-radius: 6px; font-size: 1rem; font-weight: 500; cursor: pointer; }
		button:hover { background: var(--accent-hover); }
		code { background: var(--surface); color: var(--accent); padding: 0.2em 0.45em; border-radius: 4px; font-size: 0.9em; border: 1px solid var(--border); }
	</style>
</head>
<body>
	<div x-data="{ token: '' }">
		<h1>Diag dashboard</h1>
		<p>Visit <code>/&lt;token&gt;</code> to view the dashboard for that token. Enter your token below to go there.</p>
		<div class="form-row">
			<input type="text" x-model="token" placeholder="e.g. mytoken" @keydown.enter.prevent="if(token.trim()) location.href='/'+encodeURIComponent(token.trim())">
			<button @click="if(token.trim()) location.href='/'+encodeURIComponent(token.trim())">Go</button>
		</div>
	</div>
</body>
</html>
`

// entropyHTML is the page at /entropy for port and ID entropy checks. __ZONE__ is replaced when serving.
const entropyHTML = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Entropy check (port &amp; ID)</title>
	<style>
		:root { --bg: #0f0f14; --surface: #18181f; --border: #2d2d3a; --text: #e4e4e7; --text-muted: #a1a1aa; --accent: #818cf8; --accent-hover: #6366f1; }
		html { font-size: 1.0625rem; }
		body { font-family: system-ui, -apple-system, sans-serif; max-width: 48rem; margin: 0 auto; padding: 1.5rem 2rem; line-height: 1.6; background: var(--bg); color: var(--text); min-height: 100vh; }
		h1 { font-size: 1.35rem; margin-top: 0; font-weight: 600; }
		p { color: var(--text-muted); margin: 0.5rem 0 1rem 0; }
		.result { background: var(--surface); padding: 1rem; border-radius: 6px; border: 1px solid var(--border); margin-top: 1rem; }
		.result dl { display: grid; grid-template-columns: auto 1fr; gap: 0.25rem 1.5rem; margin: 0; }
		.result dt { color: var(--text-muted); }
		.result dd { margin: 0; font-weight: 500; }
		.great { color: #22c55e; }
		.good { color: #eab308; }
		.poor { color: #ef4444; }
		#status { margin-top: 1rem; }
		.histogram { display: flex; align-items: flex-end; gap: 1px; height: 80px; margin: 0.5rem 0; max-width: 100%; min-width: 0; overflow: hidden; }
		.histogram span { flex: 1; min-width: 0; border-radius: 1px; }
		.histogram-port span { background: #22c55e; }
		.histogram-id span { background: #eab308; }
		.histogram span[data-count="0"] { opacity: 0.15; }
		.opt { margin: 0.5rem 0; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
		.opt label { color: var(--text-muted); }
		.opt input[type="number"] { width: 5rem; background: var(--surface); color: var(--text); border: 1px solid var(--border); padding: 0.25rem 0.5rem; border-radius: 4px; }
		.opt button { background: var(--accent); color: #fff; border: none; padding: 0.5rem 1rem; border-radius: 6px; font-size: 1rem; font-weight: 500; cursor: pointer; }
		.opt button:hover { background: var(--accent-hover); }
		.opt button:disabled { opacity: 0.6; cursor: not-allowed; }
		a { color: var(--accent); text-decoration: none; }
		a:hover { text-decoration: underline; }
		.note { font-size: 0.9rem; color: var(--text-muted); margin-top: 0.5rem; }
	</style>
</head>
<body>
	<h1>Entropy check (port &amp; ID)</h1>
	<p>This page measures the randomness of the DNS resolver’s source port and transaction ID. Sufficient randomness helps to prevent cache poisoning and reduces the ability of attackers to predict query parameters.</p>
	<p>Select the number of samples (100–1000). When Run is selected, the browser initiates that many DNS lookups. The server records the source port and transaction ID for each query and displays ratings, histograms, and a <a href="https://en.wikipedia.org/wiki/Chi-squared_test" target="_blank" rel="noopener">chi-squared</a> uniformity score (0–100).</p>
	<p>Port and ID ratings (GREAT / GOOD / POOR) are based on the <strong>standard deviation</strong> of the observed values. A higher spread indicates better randomness. For the Port χ² and ID χ² statistics, <strong>lower values indicate a more uniform distribution</strong>. The page also reports <a href="https://datatracker.ietf.org/doc/html/rfc5452#section-6.2" target="_blank" rel="noopener">0x20</a> QNAME case support when the resolver varies letter case in queries.</p>
	<div class="opt">
		<label for="samples">Samples:</label>
		<input type="number" id="samples" min="100" max="1000" value="250" step="1">
		<button type="button" id="runBtn">Run</button>
	</div>
	<div id="status"></div>
	<div id="result" class="result" style="display:none;"></div>
	<script>
(function() {
	var zone = '__ZONE__';
	var samplesInput = document.getElementById('samples');
	var runBtn = document.getElementById('runBtn');
	var resultEl = document.getElementById('result');
	var statusEl = document.getElementById('status');
	var MIN = 100, MAX = 1000;
	function clampSamples() {
		var val = parseInt(samplesInput.value, 10);
		if (isNaN(val) || val < MIN) { samplesInput.value = MIN; return MIN; }
		if (val > MAX) { samplesInput.value = MAX; return MAX; }
		return val;
	}
	samplesInput.addEventListener('change', clampSamples);
	samplesInput.addEventListener('blur', clampSamples);
	function runTest() {
		var N = clampSamples();
		runBtn.disabled = true;
		statusEl.textContent = 'Running…';
		resultEl.style.display = 'none';
		var runId = crypto.randomUUID().replace(/-/g, '').slice(0, 12);
		var scheme = location.protocol === 'https:' ? 'https:' : 'http:';
		for (var i = 0; i < N; i++) {
			var url = scheme + '//' + runId + '-' + i + '.entropy.' + zone + '/';
			var img = new Image();
			img.src = url;
		}
		var start = Date.now();
		var timeoutMs = N > 500 ? 60000 : 45000;
		function barChart(arr, maxVal, className) {
			var m = maxVal || Math.max.apply(null, arr);
			if (m === 0) m = 1;
			var html = '<div class="histogram ' + (className || '') + '">';
			for (var i = 0; i < arr.length; i++) {
				var h = Math.round((arr[i] / m) * 80);
				html += '<span style="height:' + h + 'px" data-count="' + arr[i] + '" title="bucket ' + i + ': ' + arr[i] + '"></span>';
			}
			html += '</div>';
			return html;
		}
		function poll() {
			if (Date.now() - start > timeoutMs) {
				statusEl.textContent = 'The request timed out.';
				runBtn.disabled = false;
				return;
			}
			fetch(location.origin + '/entropy/result/' + encodeURIComponent(runId) + '?n=' + N)
				.then(function(r) { return r.json(); })
				.then(function(data) {
					if (data.result && data.result.samples_count >= N) {
						statusEl.textContent = 'Complete.';
						runBtn.disabled = false;
						var r = data.result;
						var portCls = r.port_rating === 'GREAT' ? 'great' : (r.port_rating === 'GOOD' ? 'good' : 'poor');
						var idCls = r.id_rating === 'GREAT' ? 'great' : (r.id_rating === 'GOOD' ? 'good' : 'poor');
						var upper = r.qname_uppercase_count || 0;  // uppercase letter count across all QNAMEs
						var lower = r.qname_lowercase_count || 0;  // lowercase letter count across all QNAMEs
						var totalLetters = upper + lower;
						var upperPct = totalLetters ? (100 * upper / totalLetters).toFixed(1) : '0';
						var lowerPct = totalLetters ? (100 * lower / totalLetters).toFixed(1) : '0';
						var html = '<dl><dt>Port rating</dt><dd class="' + portCls + '">' + r.port_rating + '</dd>' +
							'<dt>Port stddev</dt><dd>' + r.port_stddev + '</dd>' +
							'<dt>Port χ²</dt><dd>' + (r.port_chi2 != null ? r.port_chi2 : '—') + '</dd>' +
							'<dt>ID rating</dt><dd class="' + idCls + '">' + r.id_rating + '</dd>' +
							'<dt>ID stddev</dt><dd>' + r.id_stddev + '</dd>' +
							'<dt>ID χ²</dt><dd>' + (r.id_chi2 != null ? r.id_chi2 : '—') + '</dd>' +
							'<dt>Samples</dt><dd>' + r.samples_count + '</dd>' +
							'<dt><a href="https://datatracker.ietf.org/doc/html/rfc5452#section-6.2" target="_blank" rel="noopener">0x20</a> Uppercase</dt><dd>' + upper + ' chars (' + upperPct + '%)</dd>' +
							'<dt><a href="https://datatracker.ietf.org/doc/html/rfc5452#section-6.2" target="_blank" rel="noopener">0x20</a> Lowercase</dt><dd>' + lower + ' chars (' + lowerPct + '%)</dd>' +
							'<dt>Randomness score</dt><dd>' + r.randomness_score + '/100 <small>(<a href="https://en.wikipedia.org/wiki/Chi-squared_test" target="_blank" rel="noopener">chi-squared</a> uniformity)</small></dd>';
						html += '</dl>';
						html += '<p style="margin-top:0.75rem;color:var(--text-muted)">Port histogram (256 buckets)</p>' + barChart(r.port_histogram || [], null, 'histogram-port');
						html += '<p style="margin-top:0.5rem;color:var(--text-muted)">Transaction ID histogram (256 buckets)</p>' + barChart(r.id_histogram || [], null, 'histogram-id');
						resultEl.innerHTML = html;
						resultEl.style.display = 'block';
						return;
					}
					statusEl.textContent = 'Running… (' + (data.samples_count || 0) + '/' + N + ' samples)';
					setTimeout(poll, 1000);
				})
				.catch(function() {
					statusEl.textContent = 'An error occurred while fetching the result.';
					runBtn.disabled = false;
				});
		}
		setTimeout(poll, 1500);
	}
	runBtn.addEventListener('click', runTest);
})();
	</script>
</body>
</html>
`
