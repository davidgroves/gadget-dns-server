package server

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/davidgroves/gadget-dns-server/internal/handler"
	"github.com/davidgroves/gadget-dns-server/internal/logging"
	"github.com/miekg/dns"
)

const dohPath = "/dns-query"
const dohContentType = "application/dns-message"

// DoHHandler returns an http.Handler that serves DoH (RFC 8484) at /dns-query.
// Use this to mount DoH on the same HTTP(S) server as the API (e.g. when DoH port equals HTTP TLS port).
// If recorder is non-nil, DNS request metrics are recorded for DoH traffic.
func DoHHandler(h *handler.Handler, recorder handler.MetricsRecorder) http.Handler {
	return &dohHandler{handler: h, recorder: recorder}
}

// dohHandler wraps a DNS handler for HTTP POST/GET (RFC 8484).
type dohHandler struct {
	handler  *handler.Handler
	recorder handler.MetricsRecorder
}

func (d *dohHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != dohPath {
		http.NotFound(w, r)
		return
	}
	start := time.Now()
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
	d.handler.FinalizeResponse(req, msg)
	if d.recorder != nil {
		qtypeStr := "UNKNOWN"
		if len(req.Question) > 0 {
			q := req.Question[0]
			qtypeStr = dns.TypeToString[q.Qtype]
			if qtypeStr == "" {
				qtypeStr = fmt.Sprintf("TYPE%d", q.Qtype)
			}
		}
		rcodeStr := dns.RcodeToString[msg.Rcode]
		if rcodeStr == "" {
			rcodeStr = fmt.Sprintf("RCODE%d", msg.Rcode)
		}
		d.recorder.RecordDNS("DoH", qtypeStr, rcodeStr, time.Since(start))
	}
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

// serveDoH starts an HTTP(S) server for DoH on addr. It blocks until the server fails.
func serveDoH(h *handler.Handler, addr string, tlsCert, tlsKey string, recorder handler.MetricsRecorder) error {
	network := tcpNetwork(addr)
	listener, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	srv := &http.Server{
		Handler: &dohHandler{handler: h, recorder: recorder},
	}
	logging.Info("DoH listening", "addr", addr, "tls", tlsCert != "")
	if tlsCert != "" && tlsKey != "" {
		return srv.ServeTLS(listener, tlsCert, tlsKey)
	}
	return srv.Serve(listener)
}
