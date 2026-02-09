package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// IPList is []net.IP with YAML unmarshaling from a list of strings.
type IPList []net.IP

// UnmarshalYAML implements yaml.Unmarshaler so server_ips can be set in YAML as a list of strings.
func (l *IPList) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var ss []string
	if err := unmarshal(&ss); err != nil {
		return err
	}
	out := make([]net.IP, 0, len(ss))
	for _, s := range ss {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			return fmt.Errorf("invalid IP %q", s)
		}
		out = append(out, ip)
	}
	*l = out
	return nil
}

// Ports holds DNS listen ports (0 = disabled for DoT/DoH/DoQ).
type Ports struct {
	UDP int `yaml:"udp" env:"GADGET_UDP_PORT"`
	TCP int `yaml:"tcp" env:"GADGET_TCP_PORT"`
	DoT int `yaml:"dot" env:"GADGET_DOT_PORT"`
	DoH int `yaml:"doh" env:"GADGET_DOH_PORT"`
	DoQ int `yaml:"doq" env:"GADGET_DOQ_PORT"`
}

// Config holds all server configuration.
type Config struct {
	// Domain is the zone apex (required for server mode).
	Domain string `yaml:"domain" env:"GADGET_DOMAIN"`
	// ConfigPath is the path to the YAML config file.
	ConfigPath string `yaml:"-" env:"GADGET_CONFIG"`

	// Ports for UDP, TCP, DoT, DoH, DoQ (0 = disabled for TLS transports).
	Ports Ports `yaml:"ports"`
	// Binds: list of addresses to bind (e.g. "0.0.0.0", "::"). Empty = bind to all.
	Binds []string `yaml:"binds" env:"GADGET_BINDS"`

	// TLS
	TLSCert string `yaml:"tls_cert" env:"GADGET_TLS_CERT"`
	TLSKey  string `yaml:"tls_key" env:"GADGET_TLS_KEY"`

	// Zone apex: NS and A/AAAA for delegation
	NSRecords []string `yaml:"ns_records" env:"GADGET_NS_RECORDS"`
	// ServerIPs are A/AAAA for zone apex, www, and diag (YAML list or GADGET_SERVER_IPS env)
	ServerIPs IPList `yaml:"server_ips" env:"-"`

	// SOA
	SOAMname   string `yaml:"soa_mname" env:"GADGET_SOA_MNAME"`
	SOARname   string `yaml:"soa_rname" env:"GADGET_SOA_RNAME"`
	SOASerial  uint32 `yaml:"soa_serial" env:"GADGET_SOA_SERIAL"`
	SOARefresh uint32 `yaml:"soa_refresh" env:"GADGET_SOA_REFRESH"`
	SOARetry   uint32 `yaml:"soa_retry" env:"GADGET_SOA_RETRY"`
	SOAExpire  uint32 `yaml:"soa_expire" env:"GADGET_SOA_EXPIRE"`
	SOAMinttl  uint32 `yaml:"soa_minttl" env:"GADGET_SOA_MINTTL"`

	// HTTP server (ACME + health + metrics + feed)
	HTTPPort    int `yaml:"http_port" env:"GADGET_HTTP_PORT"`         // e.g. 80 for ACME
	HTTPTLSPort int `yaml:"http_tls_port" env:"GADGET_HTTP_TLS_PORT"` // 0 = disabled

	// ACME
	ObtainCert     bool     `yaml:"-" env:"-"`
	ACMEDomains    []string `yaml:"acme_domains" env:"GADGET_ACME_DOMAINS"`
	ACMEIPs        []net.IP `yaml:"acme_ips" env:"GADGET_ACME_IPS"`
	ACMEAccountKey string   `yaml:"acme_account_key" env:"GADGET_ACME_ACCOUNT_KEY"`
	ACMEURL        string   `yaml:"acme_url" env:"GADGET_ACME_URL"`
	ACMERenewDays  int      `yaml:"acme_renew_days" env:"GADGET_ACME_RENEW_DAYS"` // renew when cert has less than this many days left

	// Logging
	LogLevel  string `yaml:"log_level" env:"GADGET_LOG_LEVEL"`
	LogOutput string `yaml:"log_output" env:"GADGET_LOG_OUTPUT"` // "" = stdout

	// DNSSEC
	DNSSEC        bool   `yaml:"dnssec" env:"GADGET_DNSSEC"`
	DNSSECKSKPath string `yaml:"dnssec_ksk_path" env:"GADGET_DNSSEC_KSK_PATH"`
	DNSSECZSKPath string `yaml:"dnssec_zsk_path" env:"GADGET_DNSSEC_ZSK_PATH"`
	// Publish CDS at zone apex
	DNSSECPublishCDS bool `yaml:"dnssec_publish_cds" env:"GADGET_DNSSEC_PUBLISH_CDS"`
	// RRSIG validity: inception = now - inception_offset, expiration = now + validity (e.g. "1h", "24h")
	DNSSECRRSIGInception string `yaml:"dnssec_rrsig_inception" env:"GADGET_DNSSEC_RRSIG_INCEPTION"`
	DNSSECRRSIGValidity  string `yaml:"dnssec_rrsig_validity" env:"GADGET_DNSSEC_RRSIG_VALIDITY"`

	// Diag: how long to keep diagnostic (token.diag) query data; e.g. "15m", "1h". Default 15m.
	DiagRetention string `yaml:"diag_retention" env:"GADGET_DIAG_RETENTION"`

	// Foreground (don't daemonize)
	Foreground bool `yaml:"foreground" env:"GADGET_FOREGROUND"`
}

// DefaultConfig returns defaults.
func DefaultConfig() Config {
	return Config{
		Domain:               "",
		Ports:                Ports{UDP: 53, TCP: 53},
		Binds:                nil,
		SOASerial:            1,
		SOARefresh:           86400,
		SOARetry:             7200,
		SOAExpire:            3600000,
		SOAMinttl:            60,
		HTTPPort:             80,
		HTTPTLSPort:          0,
		ACMERenewDays:        14,
		DNSSECRRSIGInception: "1h",
		DNSSECRRSIGValidity:  "24h",
		LogLevel:             "info",
		LogOutput:            "",
		DiagRetention:        "15m",
		Foreground:           true,
	}
}

// listenAddrs returns "host:port" addrs for the given port. If port <= 0 returns nil.
// If Binds is empty, returns [":port"] (all interfaces). Otherwise one addr per bind.
// When Binds contains both IPv4 any (0.0.0.0) and IPv6 any (::), we collapse to a single
// ":port" so one dual-stack socket is created instead of two (avoids "address already in use"
// on Linux where the second bind would conflict).
func (c *Config) listenAddrs(port int) []string {
	if port <= 0 {
		return nil
	}
	portStr := strconv.Itoa(port)
	if len(c.Binds) == 0 {
		return []string{":" + portStr}
	}
	has4 := false
	has6 := false
	for _, bind := range c.Binds {
		b := strings.TrimSpace(bind)
		if b == "0.0.0.0" {
			has4 = true
		}
		if b == "::" || b == "[::]" {
			has6 = true
		}
	}
	if has4 && has6 {
		return []string{":" + portStr}
	}
	addrs := make([]string, 0, len(c.Binds))
	for _, bind := range c.Binds {
		addrs = append(addrs, net.JoinHostPort(bind, portStr))
	}
	return addrs
}

// UDPAddrs returns listen addrs for UDP (from Ports.UDP + Binds).
func (c *Config) UDPAddrs() []string { return c.listenAddrs(c.Ports.UDP) }

// TCPAddrs returns listen addrs for TCP (from Ports.TCP + Binds).
func (c *Config) TCPAddrs() []string { return c.listenAddrs(c.Ports.TCP) }

// DOTAddrs returns listen addrs for DoT (from Ports.DoT + Binds).
func (c *Config) DOTAddrs() []string { return c.listenAddrs(c.Ports.DoT) }

// DOHAddrs returns listen addrs for DoH (from Ports.DoH + Binds).
func (c *Config) DOHAddrs() []string { return c.listenAddrs(c.Ports.DoH) }

// DOQAddrs returns listen addrs for DoQ (from Ports.DoQ + Binds).
func (c *Config) DOQAddrs() []string { return c.listenAddrs(c.Ports.DoQ) }

// isWildcardBind returns true for 0.0.0.0, ::, or [::].
func isWildcardBind(s string) bool {
	s = strings.TrimSpace(s)
	return s == "0.0.0.0" || s == "::" || s == "[::]"
}

// interfaceIPs returns non-loopback, non-link-local unicast addresses from all interfaces (deduplicated).
func interfaceIPs() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var out []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipn.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			key := ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, ip)
		}
	}
	return out, nil
}

// EffectiveServerIPs returns IPs to advertise for apex, www, and diag.
// If server_ips is set (YAML or GADGET_SERVER_IPS), use that. Otherwise derive from binds:
// if binds are specific IPs (no 0.0.0.0/::), use those; if binds are empty or wildcard, use interface addresses.
func (c *Config) EffectiveServerIPs() ([]net.IP, error) {
	if len(c.ServerIPs) > 0 {
		return []net.IP(c.ServerIPs), nil
	}
	if len(c.Binds) > 0 {
		allSpecific := true
		var ips []net.IP
		for _, b := range c.Binds {
			b = strings.TrimSpace(b)
			if isWildcardBind(b) {
				allSpecific = false
				break
			}
			ip := net.ParseIP(b)
			if ip == nil {
				allSpecific = false
				break
			}
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			ips = append(ips, ip)
		}
		if allSpecific && len(ips) > 0 {
			return ips, nil
		}
	}
	return interfaceIPs()
}

// Validate validates the config after merge.
func (c *Config) Validate() error {
	if c.ObtainCert {
		if c.Domain == "" {
			return fmt.Errorf("obtain-cert requires domain (DNS must be running so ACME can resolve your names)")
		}
		if len(c.ACMEDomains) == 0 && len(c.ACMEIPs) == 0 {
			return fmt.Errorf("obtain-cert requires at least one of acme_domains or acme_ips")
		}
		if c.TLSCert == "" || c.TLSKey == "" {
			return fmt.Errorf("obtain-cert requires tls_cert and tls_key output paths")
		}
		return nil
	}
	// Server mode
	if c.Domain == "" {
		return fmt.Errorf("domain is required for server mode")
	}
	if (c.Ports.DoT > 0 || c.Ports.DoH > 0 || c.Ports.DoQ > 0 || c.HTTPTLSPort > 0) && (c.TLSCert == "" || c.TLSKey == "") {
		return fmt.Errorf("TLS transports (DoT/DoH/DoQ/HTTP TLS) require tls_cert and tls_key")
	}
	if c.DNSSEC && (c.DNSSECKSKPath == "" || c.DNSSECZSKPath == "") {
		return fmt.Errorf("dnssec requires dnssec_ksk_path and dnssec_zsk_path")
	}
	return nil
}

// ParseServerIPs parses a comma-separated list of IPs (for env).
func ParseServerIPs(s string) ([]net.IP, error) {
	if s == "" {
		return nil, nil
	}
	var out []net.IP
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP %q", p)
		}
		out = append(out, ip)
	}
	return out, nil
}

// ParseACMEIPs parses comma-separated IPs for ACME.
func ParseACMEIPs(s string) ([]net.IP, error) {
	return ParseServerIPs(s)
}

// SetFromEnv sets config from environment (GADGET_*).
func (c *Config) SetFromEnv() error {
	if v := os.Getenv("GADGET_DOMAIN"); v != "" {
		c.Domain = v
	}
	if v := os.Getenv("GADGET_UDP_PORT"); v != "" {
		n, _ := strconv.Atoi(v)
		c.Ports.UDP = n
	}
	if v := os.Getenv("GADGET_TCP_PORT"); v != "" {
		n, _ := strconv.Atoi(v)
		c.Ports.TCP = n
	}
	if v := os.Getenv("GADGET_DOT_PORT"); v != "" {
		n, _ := strconv.Atoi(v)
		c.Ports.DoT = n
	}
	if v := os.Getenv("GADGET_DOH_PORT"); v != "" {
		n, _ := strconv.Atoi(v)
		c.Ports.DoH = n
	}
	if v := os.Getenv("GADGET_DOQ_PORT"); v != "" {
		n, _ := strconv.Atoi(v)
		c.Ports.DoQ = n
	}
	if v := os.Getenv("GADGET_BINDS"); v != "" {
		c.Binds = SplitTrim(v, ",")
	}
	if v := os.Getenv("GADGET_TLS_CERT"); v != "" {
		c.TLSCert = v
	}
	if v := os.Getenv("GADGET_TLS_KEY"); v != "" {
		c.TLSKey = v
	}
	if v := os.Getenv("GADGET_NS_RECORDS"); v != "" {
		c.NSRecords = SplitTrim(v, ",")
	}
	if v := os.Getenv("GADGET_SERVER_IPS"); v != "" {
		ips, err := ParseServerIPs(v)
		if err != nil {
			return err
		}
		c.ServerIPs = IPList(ips)
	}
	if v := os.Getenv("GADGET_HTTP_PORT"); v != "" {
		n, _ := strconv.Atoi(v)
		c.HTTPPort = n
	}
	if v := os.Getenv("GADGET_ACME_DOMAINS"); v != "" {
		c.ACMEDomains = SplitTrim(v, ",")
	}
	if v := os.Getenv("GADGET_ACME_IPS"); v != "" {
		ips, err := ParseACMEIPs(v)
		if err != nil {
			return err
		}
		c.ACMEIPs = ips
	}
	if v := os.Getenv("GADGET_ACME_ACCOUNT_KEY"); v != "" {
		c.ACMEAccountKey = v
	}
	if v := os.Getenv("GADGET_ACME_URL"); v != "" {
		c.ACMEURL = v
	}
	if v := os.Getenv("GADGET_ACME_RENEW_DAYS"); v != "" {
		n, _ := strconv.Atoi(v)
		c.ACMERenewDays = n
	}
	if v := os.Getenv("GADGET_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if v := os.Getenv("GADGET_DNSSEC"); v != "" {
		c.DNSSEC = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("GADGET_DNSSEC_KSK_PATH"); v != "" {
		c.DNSSECKSKPath = v
	}
	if v := os.Getenv("GADGET_DNSSEC_ZSK_PATH"); v != "" {
		c.DNSSECZSKPath = v
	}
	if v := os.Getenv("GADGET_DNSSEC_RRSIG_INCEPTION"); v != "" {
		c.DNSSECRRSIGInception = v
	}
	if v := os.Getenv("GADGET_DNSSEC_RRSIG_VALIDITY"); v != "" {
		c.DNSSECRRSIGValidity = v
	}
	if v := os.Getenv("GADGET_DIAG_RETENTION"); v != "" {
		c.DiagRetention = v
	}
	return nil
}

// ParseDiagRetention parses diag_retention (e.g. "15m", "1h"). Returns default 15 minutes if empty or invalid.
func ParseDiagRetention(s string) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return 15 * time.Minute
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 15 * time.Minute
	}
	return d
}

// ParseRRSIGDuration parses a duration string (e.g. "1h", "24h") for RRSIG inception/validity.
// Returns defaultDur if s is empty or invalid.
func ParseRRSIGDuration(s string, defaultDur time.Duration) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultDur
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultDur
	}
	return d
}

// SplitTrim splits s by sep and trims each part (used by main for CLI).
func SplitTrim(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
