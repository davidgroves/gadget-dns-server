package httpapi

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Routes configures the single HTTP server (ACME + health + metrics + feed + diag + entropy + optional DoH).
type Routes struct {
	ACME         *ACMEResponder
	Feed         *Feed
	Metrics      http.Handler
	DiagStore    *DiagStore
	DiagDomain   string        // zone for diag (e.g. example.com); empty = diag disabled
	EntropyStore *EntropyStore // optional: for /entropy page and result API
	DoHHandler   http.Handler  // optional: DoH at /dns-query (set when DoH shares port with HTTP TLS)
}

// NewRoutes creates routes with default metrics handler.
func NewRoutes(acme *ACMEResponder, feed *Feed) *Routes {
	return &Routes{
		ACME:    acme,
		Feed:    feed,
		Metrics: promhttp.Handler(),
	}
}

// ServeHTTP dispatches to root (instructions), ACME, /healthcheck, /metrics, /feed, and diag by Host/path.
func (r *Routes) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Diag dashboard: Host diag.<domain>, path /<token>
	if r.DiagStore != nil && r.DiagDomain != "" {
		host, _, _ := strings.Cut(strings.ToLower(req.Host), ":")
		host = strings.TrimSuffix(host, ".")
		domain := strings.TrimSuffix(strings.ToLower(r.DiagDomain), ".")
		if host == "diag."+domain {
			pathTrimmed := strings.Trim(strings.TrimSuffix(req.URL.Path, "/"), "/")
			pathParts := strings.Split(pathTrimmed, "/")
			if len(pathParts) == 2 && pathParts[1] == "ws" && tokenSafe.MatchString(pathParts[0]) {
				r.serveDiagWS(w, req, pathParts[0])
				return
			}
			if len(pathParts) == 1 && pathParts[0] != "" && tokenSafe.MatchString(pathParts[0]) {
				r.serveDiag(w, pathParts[0], domain)
				return
			}
			// Diag root: show token-prompt page (enter token → go to /<token>)
			if pathTrimmed == "" {
				r.serveDiagTokenPrompt(w, domain)
				return
			}
		}
	}
	if req.URL.Path == "/dns-query" && r.DoHHandler != nil {
		r.DoHHandler.ServeHTTP(w, req)
		return
	}
	// Entropy subdomain: *.entropy.<domain> → 204 so browser requests succeed
	if r.EntropyStore != nil && r.DiagDomain != "" {
		host, _, _ := strings.Cut(strings.ToLower(req.Host), ":")
		host = strings.TrimSuffix(host, ".")
		domain := strings.TrimSuffix(strings.ToLower(r.DiagDomain), ".")
		if domain != "" && (host == "entropy."+domain || strings.HasSuffix(host, ".entropy."+domain)) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	// /entropy/result/<runId>?n=100–1000
	if r.EntropyStore != nil && strings.HasPrefix(req.URL.Path, "/entropy/result/") {
		runId := strings.TrimPrefix(req.URL.Path, "/entropy/result/")
		runId = strings.TrimSuffix(runId, "/")
		if idx := strings.Index(runId, "/"); idx >= 0 {
			runId = runId[:idx]
		}
		if runId != "" {
			r.EntropyStore.ServeEntropyResult(w, req, runId)
			return
		}
	}
	switch req.URL.Path {
	case "", "/":
		r.serveIndex(w)
		return
	case "/entropy":
		if r.EntropyStore != nil {
			r.serveEntropy(w)
			return
		}
	case "/healthcheck", "/health":
		r.serveHealth(w)
		return
	case "/metrics":
		r.Metrics.ServeHTTP(w, req)
		return
	case "/feed":
		if r.Feed != nil {
			r.Feed.ServeHTTP(w, req)
			return
		}
	}
	// ACME challenge path
	if len(req.URL.Path) > len(acmeChallengePath) && req.URL.Path[:len(acmeChallengePath)] == acmeChallengePath {
		r.ACME.ServeHTTP(w, req)
		return
	}
	http.NotFound(w, req)
}

func formatDuration(d time.Duration) string {
	if d >= time.Hour {
		h := d / time.Hour
		m := (d % time.Hour) / time.Minute
		if m == 0 {
			if h == 1 {
				return "1 hour"
			}
			return fmt.Sprintf("%d hours", h)
		}
		if h == 1 && m == 1 {
			return "1 hour 1 minute"
		}
		return fmt.Sprintf("%d hours %d minutes", h, m)
	}
	if d >= time.Minute {
		m := d / time.Minute
		if m == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", m)
	}
	s := d / time.Second
	if s <= 1 {
		return "1 second"
	}
	return fmt.Sprintf("%d seconds", s)
}

func (r *Routes) serveDiag(w http.ResponseWriter, token, domain string) {
	records := r.DiagStore.Records(token)
	retentionStr := formatDuration(r.DiagStore.Retention())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!DOCTYPE html><html lang="en"><head><meta charset=utf-8><meta name="viewport" content="width=device-width, initial-scale=1"><title>Diag %s</title>
<style>:root{--bg:#0f0f14;--surface:#18181f;--border:#2d2d3a;--text:#e4e4e7;--text-muted:#a1a1aa;--accent:#818cf8;}
html{font-size:1.0625rem;}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);margin:0;padding:1.5rem 2rem;line-height:1.5;}
h1{font-size:1.25rem;margin-top:0;}
p.diag-meta{color:var(--text-muted);font-size:0.9em;margin:0.25rem 0 1rem 0;}
code{background:var(--surface);color:var(--accent);padding:0.2em 0.45em;border-radius:4px;font-size:0.9em;border:1px solid var(--border);}
table{border-collapse:collapse;width:100%%;}
th,td{border:1px solid var(--border);padding:0.5rem 0.75rem;text-align:left;}
th{background:var(--surface);color:var(--text-muted);font-weight:600;}
.diag-detail{font-family:monospace;font-size:0.75rem;white-space:pre;background:var(--surface);color:var(--text-muted);padding:8px;margin:4px 0;border:1px solid var(--border);border-radius:4px;}
.diag-hex{font-size:0.6875rem;margin-top:8px;}
.diag-copy-hex{font-size:0.6875rem;margin-bottom:6px;padding:4px 8px;cursor:pointer;background:var(--surface);color:var(--accent);border:1px solid var(--border);border-radius:4px;}
.diag-related{margin-top:0.5rem;margin-left:1rem;border-left:2px solid var(--border);padding-left:0.75rem;}</style></head><body>
<h1>DNS queries for %s.diag.%s</h1><p class="diag-meta">Data retained for %s.</p>
<table><tr><th>Time</th><th>Qname</th><th>Qtype</th><th>Client</th><th>Transport</th><th>Detail</th></tr>`,
		html.EscapeString(token), html.EscapeString(token), html.EscapeString(domain), html.EscapeString(retentionStr))
	for _, rec := range records {
		e := rec.Primary
		ts := html.EscapeString(e.Timestamp)
		qname := html.EscapeString(e.Qname)
		qtype := html.EscapeString(e.Qtype)
		client := html.EscapeString(e.ClientAddr)
		transport := html.EscapeString(e.Transport)
		fmt.Fprintf(w, "<tr data-primary-ts=%q><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>",
			e.Timestamp, ts, qname, qtype, client, transport)
		// Expandable detail: Request and Response decode + optional hex
		fmt.Fprint(w, "<details><summary>Request / Response</summary>")
		writeEventDetail(w, &e)
		fmt.Fprint(w, "</details>")
		if len(rec.Related) > 0 {
			fmt.Fprint(w, "<div class=diag-related><strong>Related queries (e.g. validation)</strong>")
			for _, rel := range rec.Related {
				fmt.Fprintf(w, "<details><summary>%s %s — %s</summary>",
					html.EscapeString(rel.Qname), html.EscapeString(rel.Qtype), html.EscapeString(rel.Timestamp))
				writeEventDetail(w, &rel)
				fmt.Fprint(w, "</details>")
			}
			fmt.Fprint(w, "</div>")
		}
		fmt.Fprint(w, "</td></tr>")
	}
	fmt.Fprint(w, "</table>")
	r.writeDiagLiveScript(w, token)
	fmt.Fprint(w, "</body></html>")
}

func (r *Routes) writeDiagLiveScript(w http.ResponseWriter, token string) {
	// Live updates via WebSocket; token is only for server-side path, WS URL is derived from location
	fmt.Fprint(w, `<p class="diag-meta" id="diag-live-status">Connecting for live updates…</p>`)
	fmt.Fprint(w, `<script>
(function(){
	var scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
	var wsUrl = scheme + '//' + location.host + location.pathname + '/ws';
	var table = document.querySelector('table');
	var statusEl = document.getElementById('diag-live-status');
	function esc(s) { if (s == null) return ''; var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
	function connect() {
		var ws = new WebSocket(wsUrl);
		ws.onopen = function() { statusEl.textContent = 'Live updates connected.'; };
		ws.onclose = function() { statusEl.textContent = 'Live updates paused. Refresh to reconnect.'; };
		ws.onerror = function() { statusEl.textContent = 'Live updates error.'; };
		ws.onmessage = function(ev) {
			try {
				var msg = JSON.parse(ev.data);
				if (msg.type === 'snapshot') return;
				if (msg.type === 'record') {
					var p = msg.record.primary;
					var tr = document.createElement('tr');
					tr.setAttribute('data-primary-ts', p.timestamp || '');
					tr.innerHTML = '<td>' + esc(p.timestamp) + '</td><td>' + esc(p.qname) + '</td><td>' + esc(p.qtype) + '</td><td>' + esc(p.client_addr) + '</td><td>' + esc(p.transport) + '</td><td>' + (msg.detail_html || '') + '</td>';
					table.appendChild(tr);
				} else if (msg.type === 'related') {
					var ts = (msg.record && msg.record.primary && msg.record.primary.timestamp) ? msg.record.primary.timestamp : '';
					var rows = table.querySelectorAll('tr[data-primary-ts]');
					for (var i = 0; i < rows.length; i++) {
						if (rows[i].getAttribute('data-primary-ts') === ts && rows[i].cells && rows[i].cells[5]) {
							rows[i].cells[5].innerHTML = msg.detail_html || '';
							break;
						}
					}
				}
			} catch (e) {}
		};
	}
	connect();
	document.body.addEventListener('click', function(e) {
		var btn = e.target.closest('.diag-copy-hex');
		if (!btn || !btn.dataset.rawHex) return;
		navigator.clipboard.writeText(btn.dataset.rawHex).then(function() {
			var t = btn.textContent;
			btn.textContent = 'Copied!';
			setTimeout(function() { btn.textContent = t; }, 1500);
		});
	});
})();
</script>`)
}

var diagWSUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

const diagWSWriteTimeout = 10 * time.Second

func (r *Routes) serveDiagWS(w http.ResponseWriter, req *http.Request, token string) {
	conn, err := diagWSUpgrader.Upgrade(w, req, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	snapshot, updates, unsubscribe := r.DiagStore.Subscribe(token)
	defer unsubscribe()

	// Send initial snapshot
	snapshotMsg := struct {
		Type    string       `json:"type"`
		Records []DiagRecord `json:"records"`
	}{Type: "snapshot", Records: snapshot}
	if err := conn.SetWriteDeadline(time.Now().Add(diagWSWriteTimeout)); err == nil {
		_ = conn.WriteJSON(snapshotMsg)
	}

	// Stream updates
	for u := range updates {
		if err := conn.SetWriteDeadline(time.Now().Add(diagWSWriteTimeout)); err != nil {
			return
		}
		if err := conn.WriteJSON(u); err != nil {
			return
		}
	}
}

func writeEventDetail(w http.ResponseWriter, e *Event) {
	_, _ = w.Write([]byte(eventDetailHTML(e)))
}

// eventDetailHTML returns the HTML for one event's request/response detail (for server-rendered and WS).
func eventDetailHTML(e *Event) string {
	var b strings.Builder
	if len(e.RequestWire) > 0 {
		b.WriteString("<div class=diag-detail><strong>Request</strong>\n")
		b.WriteString(FormatDNSMsgHTML(e.RequestWire))
		writeHexBlock(&b, e.RequestWire)
		b.WriteString("</div>")
	} else {
		b.WriteString("<div class=diag-detail><strong>Request</strong> (no wire data)</div>")
	}
	if len(e.ResponseWire) > 0 {
		b.WriteString("<div class=diag-detail><strong>Response</strong>\n")
		b.WriteString(FormatDNSMsgHTML(e.ResponseWire))
		writeHexBlock(&b, e.ResponseWire)
		b.WriteString("</div>")
	} else {
		b.WriteString("<div class=diag-detail><strong>Response</strong> (no wire data)</div>")
	}
	return b.String()
}

func writeHexBlock(b *strings.Builder, wire []byte) {
	rawHex := RawHex(wire)
	fmt.Fprintf(b, "\n<details class=diag-hex><summary>Raw (hex)</summary><button type=button class=diag-copy-hex data-raw-hex=\"%s\">Copy hex</button><pre>%s</pre></details>",
		html.EscapeString(rawHex), html.EscapeString(HexDump(wire)))
}

// recordDetailHTML returns the full detail cell HTML for a DiagRecord (primary + related).
func recordDetailHTML(rec *DiagRecord) string {
	var b strings.Builder
	b.WriteString("<details><summary>Request / Response</summary>")
	b.WriteString(eventDetailHTML(&rec.Primary))
	if len(rec.Related) > 0 {
		b.WriteString("<div class=diag-related><strong>Related queries (e.g. validation)</strong>")
		for _, rel := range rec.Related {
			fmt.Fprintf(&b, "<details><summary>%s %s — %s</summary>",
				html.EscapeString(rel.Qname), html.EscapeString(rel.Qtype), html.EscapeString(rel.Timestamp))
			b.WriteString(eventDetailHTML(&rel))
			b.WriteString("</details>")
		}
		b.WriteString("</div>")
	}
	b.WriteString("</details>")
	return b.String()
}

// DiagRelatedWindow is how long after a diag event we attach related queries from the same client (e.g. DNSKEY).
const DiagRelatedWindow = 30 * time.Second

// DiagRecord is one diag row: the primary query (token.diag.<zone>) and optional related queries (e.g. validation).
type DiagRecord struct {
	Primary Event   `json:"primary"`
	Related []Event `json:"related,omitempty"`
}

// DiagUpdate is a WebSocket message: "record" = new primary record, "related" = existing record had a related event appended.
type DiagUpdate struct {
	Type       string     `json:"type"`        // "record" or "related"
	Record     DiagRecord `json:"record"`      // the record (new or updated)
	DetailHTML string     `json:"detail_html"` // pre-rendered detail cell HTML for client to insert
}

// diagSub is a single subscriber channel for a token.
type diagSub struct {
	ch chan DiagUpdate
}

const diagSubBuffer = 64

// DiagStore holds DNS query events per token (for token.diag.<zone>).
// Events are pruned after retention; this is how long diagnostic data is kept.
type DiagStore struct {
	mu          sync.RWMutex
	byToken     map[string][]DiagRecord
	maxPerToken int
	retention   time.Duration
	subMu       sync.Mutex
	subs        map[string][]*diagSub
}

// NewDiagStore creates a store with a per-token cap (e.g. 100) and retention (e.g. 15*time.Minute).
// Diagnostic data older than retention is pruned and not returned.
func NewDiagStore(maxPerToken int, retention time.Duration) *DiagStore {
	if maxPerToken <= 0 {
		maxPerToken = 100
	}
	if retention <= 0 {
		retention = 15 * time.Minute
	}
	return &DiagStore{
		byToken:     make(map[string][]DiagRecord),
		maxPerToken: maxPerToken,
		retention:   retention,
		subs:        make(map[string][]*diagSub),
	}
}

// Retention returns how long diagnostic data is kept before pruning.
func (d *DiagStore) Retention() time.Duration {
	return d.retention
}

func (d *DiagStore) pruneLocked(list []DiagRecord, cutoff time.Time) []DiagRecord {
	out := list[:0]
	for _, rec := range list {
		t, err := time.Parse(time.RFC3339, rec.Primary.Timestamp)
		if err != nil {
			continue
		}
		if !t.Before(cutoff) {
			out = append(out, rec)
		}
	}
	return out
}

// Record adds a primary diag event for the token (ring buffer per token). Prunes records older than retention.
func (d *DiagStore) Record(token string, e Event) {
	d.mu.Lock()
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	list := d.byToken[token]
	cutoff := time.Now().UTC().Add(-d.retention)
	list = d.pruneLocked(list, cutoff)
	if len(list) >= d.maxPerToken {
		list = list[1:]
	}
	rec := DiagRecord{Primary: e, Related: nil}
	d.byToken[token] = append(list, rec)
	d.mu.Unlock()
	d.broadcast(token, DiagUpdate{Type: "record", Record: rec, DetailHTML: recordDetailHTML(&rec)})
}

// AppendRelated attaches a related event (e.g. DNSKEY from same client) to the most recent diag record
// for the token from that client within DiagRelatedWindow. If none is found, the event is dropped.
func (d *DiagStore) AppendRelated(token string, clientAddr string, e Event) {
	d.mu.Lock()
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	list := d.byToken[token]
	if len(list) == 0 {
		d.mu.Unlock()
		return
	}
	cutoff := time.Now().UTC().Add(-DiagRelatedWindow)
	// Find most recent record from this client within the related window (list is oldest-first).
	var best *DiagRecord
	var bestT time.Time
	for i := range list {
		rec := &list[i]
		if rec.Primary.ClientAddr != clientAddr {
			continue
		}
		t, err := time.Parse(time.RFC3339, rec.Primary.Timestamp)
		if err != nil || t.Before(cutoff) {
			continue
		}
		if t.After(bestT) {
			bestT = t
			best = rec
		}
	}
	if best != nil {
		best.Related = append(best.Related, e)
		recCopy := *best
		recCopy.Related = make([]Event, len(best.Related))
		copy(recCopy.Related, best.Related)
		d.mu.Unlock()
		d.broadcast(token, DiagUpdate{Type: "related", Record: recCopy, DetailHTML: recordDetailHTML(&recCopy)})
		return
	}
	d.mu.Unlock()
}

// broadcast sends an update to all subscribers for the token. Non-blocking; drops if channel full.
func (d *DiagStore) broadcast(token string, u DiagUpdate) {
	d.subMu.Lock()
	list := d.subs[token]
	if len(list) == 0 {
		d.subMu.Unlock()
		return
	}
	// copy slice so we can unlock before sending
	subs := make([]*diagSub, len(list))
	copy(subs, list)
	d.subMu.Unlock()
	for _, sub := range subs {
		select {
		case sub.ch <- u:
		default:
			// client slow; drop
		}
	}
}

// Subscribe returns the current snapshot and a channel of updates for the token. Call unsubscribe when done.
func (d *DiagStore) Subscribe(token string) (snapshot []DiagRecord, updates <-chan DiagUpdate, unsubscribe func()) {
	snapshot = d.Records(token)
	ch := make(chan DiagUpdate, diagSubBuffer)
	sub := &diagSub{ch: ch}
	d.subMu.Lock()
	d.subs[token] = append(d.subs[token], sub)
	d.subMu.Unlock()
	unsubscribe = func() {
		d.subMu.Lock()
		list := d.subs[token]
		for i, s := range list {
			if s == sub {
				d.subs[token] = append(list[:i], list[i+1:]...)
				break
			}
		}
		d.subMu.Unlock()
		close(ch)
	}
	return snapshot, ch, unsubscribe
}

// Records returns a copy of diag records for the token within the retention window (newest last).
func (d *DiagStore) Records(token string) []DiagRecord {
	d.mu.RLock()
	cutoff := time.Now().UTC().Add(-d.retention)
	list := d.byToken[token]
	var out []DiagRecord
	for _, rec := range list {
		t, err := time.Parse(time.RFC3339, rec.Primary.Timestamp)
		if err != nil {
			continue
		}
		if !t.Before(cutoff) {
			out = append(out, rec)
		}
	}
	d.mu.RUnlock()
	return out
}

func (r *Routes) serveIndex(w http.ResponseWriter) {
	zone := strings.TrimSuffix(strings.ToLower(r.DiagDomain), ".")
	if zone == "" {
		zone = "example.com"
	}
	body := strings.ReplaceAll(indexHTML, indexZonePlaceholder, zone)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

func (r *Routes) serveDiagTokenPrompt(w http.ResponseWriter, domain string) {
	zone := strings.TrimSuffix(strings.ToLower(domain), ".")
	if zone == "" {
		zone = "example.com"
	}
	body := strings.ReplaceAll(diagTokenPromptHTML, indexZonePlaceholder, zone)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

func (r *Routes) serveEntropy(w http.ResponseWriter) {
	zone := strings.TrimSuffix(strings.ToLower(r.DiagDomain), ".")
	if zone == "" {
		zone = "example.com"
	}
	body := strings.ReplaceAll(entropyHTML, indexZonePlaceholder, zone)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

func (r *Routes) serveHealth(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// Feed streams query/response events (SSE or NDJSON).
type Feed struct {
	mu     sync.RWMutex
	events []Event
	max    int
}

// Event is one query/response event for the feed and diag.
type Event struct {
	ClientAddr   string `json:"client_addr"`
	Transport    string `json:"transport"`
	Qname        string `json:"qname"`
	Qtype        string `json:"qtype"`
	Rcode        int    `json:"rcode"`
	LatencyMs    int64  `json:"latency_ms,omitempty"`
	Timestamp    string `json:"timestamp,omitempty"`
	RequestWire  []byte `json:"request_wire,omitempty"`  // raw DNS request (diag)
	ResponseWire []byte `json:"response_wire,omitempty"` // raw DNS response (diag)
}

// NewFeed creates a feed with a ring buffer of max events.
func NewFeed(max int) *Feed {
	if max <= 0 {
		max = 1000
	}
	return &Feed{events: make([]Event, 0, max), max: max}
}

// Push adds an event (drops oldest if at capacity).
func (f *Feed) Push(e Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.events) >= f.max {
		f.events = f.events[1:]
	}
	f.events = append(f.events, e)
}

// ServeHTTP streams events as NDJSON (one JSON object per line).
func (f *Feed) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	f.mu.RLock()
	snapshot := make([]Event, len(f.events))
	copy(snapshot, f.events)
	f.mu.RUnlock()
	enc := json.NewEncoder(w)
	for _, e := range snapshot {
		_ = enc.Encode(e)
	}
}
