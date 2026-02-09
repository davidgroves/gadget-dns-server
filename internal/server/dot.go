package server

import (
	"crypto/tls"
	"fmt"

	"github.com/davidgroves/gadget-dns-server/internal/logging"
	"github.com/miekg/dns"
)

// serveDoT starts a DNS over TLS listener on addr. It blocks until the listener fails.
func serveDoT(h dns.Handler, addr, tlsCert, tlsKey string) error {
	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return fmt.Errorf("dot tls: %w", err)
	}
	network := tcpNetwork(addr)
	listener, err := tls.Listen(network, addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		return fmt.Errorf("dot listen %s: %w", addr, err)
	}
	defer listener.Close()
	logging.Info("DoT listening", "addr", addr)
	srv := &dns.Server{Listener: listener, Handler: h}
	return srv.ActivateAndServe()
}
