package server

import (
	"encoding/base64"
	"io"
	"net/http"
	"strconv"

	"github.com/davidgroves/gadget-dns-server/internal/handler"
	"github.com/davidgroves/gadget-dns-server/internal/logging"
	"github.com/miekg/dns"
)

const dohPath = "/dns-query"
const dohContentType = "application/dns-message"

// dohHandler wraps a DNS handler for HTTP POST/GET (RFC 8484).
type dohHandler struct {
	handler *handler.Handler
}

func (d *dohHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != dohPath {
		http.NotFound(w, r)
		return
	}
	var body []byte
	var err error
	switch r.Method {
	case http.MethodPost:
		if r.Header.Get("Content-Type") != dohContentType {
			http.Error(w, "bad content-type", http.StatusUnsupportedMediaType)
			return
		}
		body, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		body, err = base64.RawURLEncoding.DecodeString(q)
		if err != nil {
			http.Error(w, "invalid dns parameter", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	req := new(dns.Msg)
	if err := req.Unpack(body); err != nil {
		http.Error(w, "invalid dns message", http.StatusBadRequest)
		return
	}
	// DoH: client address from HTTP connection
	addr := r.RemoteAddr
	msg := d.handler.Handle(req, &dohAddr{addr: addr}, "DoH")
	packed, err := msg.Pack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", dohContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packed)
}

type dohAddr struct{ addr string }

func (a *dohAddr) Network() string { return "tcp" }
func (a *dohAddr) String() string  { return a.addr }

// serveDoH starts an HTTP(S) server for DoH. It blocks until the server fails.
func serveDoH(h *handler.Handler, port int, tlsCert, tlsKey string) error {
	if port <= 0 {
		port = 443
	}
	addr := ":" + strconv.Itoa(port)
	srv := &http.Server{
		Addr:    addr,
		Handler: &dohHandler{handler: h},
	}
	logging.Info("DoH listening", "port", port, "tls", tlsCert != "")
	if tlsCert != "" && tlsKey != "" {
		return srv.ListenAndServeTLS(tlsCert, tlsKey)
	}
	return srv.ListenAndServe()
}
