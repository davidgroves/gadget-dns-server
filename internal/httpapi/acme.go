package httpapi

import (
	"net/http"
	"path"
	"regexp"
	"sync"
)

const acmeChallengePath = "/.well-known/acme-challenge/"

var tokenSafe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ACMEResponder serves ACME HTTP-01 challenge responses.
type ACMEResponder struct {
	mu    sync.RWMutex
	chals map[string]string // token -> key authorization
}

// NewACMEResponder creates a new ACME challenge responder.
func NewACMEResponder() *ACMEResponder {
	return &ACMEResponder{chals: make(map[string]string)}
}

// Set stores the response for the given token.
func (c *ACMEResponder) Set(token, response string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chals[token] = response
}

// ServeHTTP implements http.Handler for GET /.well-known/acme-challenge/<token>.
func (c *ACMEResponder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if path.Clean(r.URL.Path) != r.URL.Path {
		http.NotFound(w, r)
		return
	}
	if len(r.URL.Path) <= len(acmeChallengePath) {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path[:len(acmeChallengePath)] != acmeChallengePath {
		http.NotFound(w, r)
		return
	}
	token := r.URL.Path[len(acmeChallengePath):]
	if !tokenSafe.MatchString(token) {
		http.NotFound(w, r)
		return
	}
	c.mu.RLock()
	response, ok := c.chals[token]
	c.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(response))
}
