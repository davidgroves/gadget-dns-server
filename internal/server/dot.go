package server

import (
	"crypto/tls"
	"fmt"

	"github.com/davidgroves/gadget-dns-server/internal/logging"
	"github.com/miekg/dns"
)

// serveDoT starts a DNS over TLS listener. It blocks until the listener fails.
func serveDoT(h dns.Handler, port int, tlsCert, tlsKey string) error {
	if port <= 0 {
		port = 853
	}
	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return fmt.Errorf("dot tls: %w", err)
	}
	addr := ResolveAddr("", port)
	listener, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		return fmt.Errorf("dot listen: %w", err)
	}
	defer listener.Close()
	logging.Info("DoT listening", "port", port)
	srv := &dns.Server{Listener: listener, Handler: h}
	return srv.ActivateAndServe()
}
