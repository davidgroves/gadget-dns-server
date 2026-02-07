package server

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/davidgroves/gadget-dns-server/internal/handler"
	"github.com/davidgroves/gadget-dns-server/internal/logging"
	"github.com/miekg/dns"
)

// Config for the DNS server.
type Config struct {
	Handler *handler.Handler
	// UDP/TCP
	UDPAddrs []string
	TCPAddrs []string
	// TLS transports (0 = disabled)
	DOTPort int
	DOHPort int
	DOQPort int
	TLSCert string
	TLSKey  string
}

// Server runs UDP, TCP, and optionally DoT/DoH/DoQ listeners.
type Server struct {
	cfg     Config
	closers []func()
	mu      sync.Mutex
}

// New creates a new Server.
func New(cfg Config) *Server {
	return &Server{cfg: cfg}
}

// Start starts all configured listeners.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.cfg.Handler
	if h == nil {
		return fmt.Errorf("handler is required")
	}

	for _, addr := range s.cfg.UDPAddrs {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return fmt.Errorf("resolve udp %s: %w", addr, err)
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("udp listen %s: %w", addr, err)
		}
		s.closers = append(s.closers, func() { conn.Close() })
		go func(c *net.UDPConn) {
			_ = dns.ActivateAndServe(nil, c, &transportHandler{transport: "UDP", handler: h})
		}(conn)
		logging.Info("UDP listening", "addr", addr)
	}

	for _, addr := range s.cfg.TCPAddrs {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("tcp listen %s: %w", addr, err)
		}
		s.closers = append(s.closers, func() { l.Close() })
		go func(ln net.Listener) {
			_ = dns.ActivateAndServe(ln, nil, &transportHandler{transport: "TCP", handler: h})
		}(l)
		logging.Info("TCP listening", "addr", addr)
	}

	if s.cfg.DOTPort > 0 && s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		go func() {
			if err := serveDoT(&transportHandler{transport: "DoT", handler: s.cfg.Handler}, s.cfg.DOTPort, s.cfg.TLSCert, s.cfg.TLSKey); err != nil {
				logging.Error("DoT server failed", "err", err)
			}
		}()
	}
	if s.cfg.DOHPort > 0 {
		go func() {
			if err := serveDoH(s.cfg.Handler, s.cfg.DOHPort, s.cfg.TLSCert, s.cfg.TLSKey); err != nil {
				logging.Error("DoH server failed", "err", err)
			}
		}()
	}
	if s.cfg.DOQPort > 0 && s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		go func() {
			if err := serveDoQ(context.Background(), s.cfg.Handler, s.cfg.DOQPort, s.cfg.TLSCert, s.cfg.TLSKey); err != nil {
				logging.Error("DoQ server failed", "err", err)
			}
		}()
	}
	return nil
}

// transportHandler wraps a handler and injects transport into the ResponseWriter.
type transportHandler struct {
	transport string
	handler   *handler.Handler
}

func (t *transportHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	t.handler.ServeDNS(&transportResponseWriter{ResponseWriter: w, transport: t.transport}, r)
}

// transportResponseWriter implements handler.TransportWriter.
type transportResponseWriter struct {
	dns.ResponseWriter
	transport string
}

func (t *transportResponseWriter) Transport() string { return t.transport }

// Close stops all listeners.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, fn := range s.closers {
		fn()
	}
	s.closers = nil
}

// ResolveAddr returns "host:port" for the given port if host is empty.
func ResolveAddr(host string, port int) string {
	if port <= 0 {
		port = 53
	}
	if host == "" {
		return ":" + strconv.Itoa(port)
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
