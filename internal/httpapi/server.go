package httpapi

import (
	"crypto/tls"
	"net/http"
	"strconv"

	"github.com/davidgroves/gadget-dns-server/internal/logging"
)

// Server is the single HTTP server (ACME + health + metrics + feed).
type Server struct {
	Port          int
	TLSPort       int
	TLSCert       string
	TLSKey        string
	Routes        *Routes
	acmeResponder *ACMEResponder
}

// NewServer creates an HTTP server with the given routes.
func NewServer(port int, routes *Routes) *Server {
	if port <= 0 {
		port = 80
	}
	return &Server{
		Port:          port,
		Routes:        routes,
		acmeResponder: routes.ACME,
	}
}

// ACMEResponder returns the ACME challenge responder (for use by acme client).
func (s *Server) ACMEResponder() *ACMEResponder {
	return s.acmeResponder
}

// Start starts the plain HTTP listener (and optionally TLS).
func (s *Server) Start() error {
	// Plain HTTP (for ACME HTTP-01)
	addr := ":" + strconv.Itoa(s.Port)
	go func() {
		logging.Info("HTTP server listening", "port", s.Port)
		if err := http.ListenAndServe(addr, s.Routes); err != nil && err != http.ErrServerClosed {
			logging.Error("HTTP server failed", "err", err)
		}
	}()
	// Optional TLS (same routes)
	if s.TLSPort > 0 && s.TLSCert != "" && s.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(s.TLSCert, s.TLSKey)
		if err != nil {
			return err
		}
		tlsAddr := ":" + strconv.Itoa(s.TLSPort)
		tlsSrv := &http.Server{
			Addr:      tlsAddr,
			Handler:   s.Routes,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		}
		go func() {
			logging.Info("HTTP TLS server listening", "port", s.TLSPort)
			if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				logging.Error("HTTP TLS server failed", "err", err)
			}
		}()
	}
	return nil
}
