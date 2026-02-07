package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Routes configures the single HTTP server (ACME + health + metrics + feed + diag).
type Routes struct {
	ACME       *ACMEResponder
	Feed       *Feed
	Metrics    http.Handler
	DiagStore  *DiagStore
	DiagDomain string // zone for diag (e.g. example.com); empty = diag disabled
}

// NewRoutes creates routes with default metrics handler.
func NewRoutes(acme *ACMEResponder, feed *Feed) *Routes {
	return &Routes{
		ACME:    acme,
		Feed:    feed,
		Metrics: promhttp.Handler(),
	}
}

// ServeHTTP dispatches to root (instructions), ACME, /healthcheck, /metrics, /feed, and diag by Host.
func (r *Routes) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Diag dashboard: Host <token>.diag.<domain>
	if r.DiagStore != nil && r.DiagDomain != "" {
		host := strings.TrimSuffix(strings.ToLower(req.Host), ".")
		domain := strings.TrimSuffix(strings.ToLower(r.DiagDomain), ".")
		suffix := ".diag." + domain
		if strings.HasSuffix(host, suffix) {
			token := strings.TrimSuffix(host, suffix)
			if token != "" && !strings.Contains(token, ".") {
				r.serveDiag(w, token, domain)
				return
			}
		}
	}
	switch req.URL.Path {
	case "", "/":
		r.serveIndex(w)
		return
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

func (r *Routes) serveDiag(w http.ResponseWriter, token, domain string) {
	events := r.DiagStore.Events(token)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "<!DOCTYPE html><html><head><meta charset=utf-8><title>Diag %s</title></head><body><h1>DNS queries for %s.diag.%s</h1><p>View at <code>https://%s.diag.%s</code></p><table border=1><tr><th>Time</th><th>Qname</th><th>Qtype</th><th>Client</th><th>Transport</th></tr>",
		token, token, domain, token, domain)
	for _, e := range events {
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			e.Timestamp, e.Qname, e.Qtype, e.ClientAddr, e.Transport)
	}
	fmt.Fprint(w, "</table></body></html>")
}

// DiagStore holds DNS query events per token (for token.diag.<zone>).
type DiagStore struct {
	mu          sync.RWMutex
	byToken     map[string][]Event
	maxPerToken int
}

// NewDiagStore creates a store with a per-token cap (e.g. 100).
func NewDiagStore(maxPerToken int) *DiagStore {
	if maxPerToken <= 0 {
		maxPerToken = 100
	}
	return &DiagStore{byToken: make(map[string][]Event), maxPerToken: maxPerToken}
}

// Record adds an event for the token (ring buffer per token).
func (d *DiagStore) Record(token string, e Event) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	list := d.byToken[token]
	if len(list) >= d.maxPerToken {
		list = list[1:]
	}
	d.byToken[token] = append(list, e)
}

// Events returns a copy of events for the token (newest last).
func (d *DiagStore) Events(token string) []Event {
	d.mu.RLock()
	defer d.mu.RUnlock()
	list := d.byToken[token]
	out := make([]Event, len(list))
	copy(out, list)
	return out
}

func (r *Routes) serveIndex(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(indexHTML))
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

// Event is one query/response event for the feed.
type Event struct {
	ClientAddr string `json:"client_addr"`
	Transport  string `json:"transport"`
	Qname      string `json:"qname"`
	Qtype      string `json:"qtype"`
	Rcode      int    `json:"rcode"`
	LatencyMs  int64  `json:"latency_ms,omitempty"`
	Timestamp  string `json:"timestamp,omitempty"`
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
