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
	// TLS transports (listen addrs, e.g. "0.0.0.0:853", "[::]:853")
	DOTAddrs []string
	DOHAddrs []string
	DOQAddrs []string
	TLSCert  string
	TLSKey   string
	// Optional metrics recorder for DNS requests (UDP/TCP/DoT/DoQ use handler's; DoH dedicated port uses this)
	MetricsRecorder handler.MetricsRecorder
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
		network := udpNetwork(udpAddr)
		conn, err := net.ListenUDP(network, udpAddr)
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
		network := tcpNetwork(addr)
		l, err := net.Listen(network, addr)
		if err != nil {
			return fmt.Errorf("tcp listen %s: %w", addr, err)
		}
		s.closers = append(s.closers, func() { l.Close() })
		go func(ln net.Listener) {
			_ = dns.ActivateAndServe(ln, nil, &transportHandler{transport: "TCP", handler: h})
		}(l)
		logging.Info("TCP listening", "addr", addr)
	}

	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		for _, addr := range s.cfg.DOTAddrs {
			addr := addr
			go func() {
				if err := serveDoT(&transportHandler{transport: "DoT", handler: s.cfg.Handler}, addr, s.cfg.TLSCert, s.cfg.TLSKey); err != nil {
					logging.Error("DoT server failed", "addr", addr, "err", err)
				}
			}()
		}
		for _, addr := range s.cfg.DOQAddrs {
			addr := addr
			go func() {
				if err := serveDoQ(context.Background(), s.cfg.Handler, addr, s.cfg.TLSCert, s.cfg.TLSKey); err != nil {
					logging.Error("DoQ server failed", "addr", addr, "err", err)
				}
			}()
		}
	}
	for _, addr := range s.cfg.DOHAddrs {
		addr := addr
		go func() {
			if err := serveDoH(s.cfg.Handler, addr, s.cfg.TLSCert, s.cfg.TLSKey, s.cfg.MetricsRecorder); err != nil {
				logging.Error("DoH server failed", "addr", addr, "err", err)
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

// udpNetwork returns "udp6", "udp4", or "udp". Use udp4/udp6 when binding both 0.0.0.0 and [::]
// so they don't conflict on Linux (IPv6 socket is v6-only); use "udp" for unspecified.
func udpNetwork(addr *net.UDPAddr) string {
	if addr.IP == nil {
		return "udp"
	}
	if addr.IP.To4() == nil {
		return "udp6"
	}
	return "udp4"
}

// tcpNetwork returns "tcp6", "tcp4", or "tcp". Use tcp4/tcp6 when binding both 0.0.0.0 and [::]
// so they don't conflict on Linux; use "tcp" for a single unspecified address (e.g. ":53").
func tcpNetwork(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "tcp"
	}
	if host == "" {
		return "tcp"
	}
	if host == "::" {
		return "tcp6"
	}
	if host == "0.0.0.0" {
		return "tcp4"
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "tcp6"
	}
	return "tcp4"
}
