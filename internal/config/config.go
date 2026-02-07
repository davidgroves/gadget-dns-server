package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all server configuration.
type Config struct {
	// Domain is the zone apex (required for server mode).
	Domain string `yaml:"domain" env:"GADGET_DOMAIN"`
	// ConfigPath is the path to the YAML config file.
	ConfigPath string `yaml:"-" env:"GADGET_CONFIG"`

	// UDP addrs: "host:port" or ":53"
	UDPAddrs []string `yaml:"udp_addrs" env:"GADGET_UDP_ADDRS"`
	// TCP addrs
	TCPAddrs []string `yaml:"tcp_addrs" env:"GADGET_TCP_ADDRS"`
	// DoT port (0 = disabled)
	DOTPort int `yaml:"dot_port" env:"GADGET_DOT_PORT"`
	// DoH port (0 = disabled)
	DOHPort int `yaml:"doh_port" env:"GADGET_DOH_PORT"`
	// DoQ port (0 = disabled)
	DOQPort int `yaml:"doq_port" env:"GADGET_DOQ_PORT"`

	// TLS
	TLSCert string `yaml:"tls_cert" env:"GADGET_TLS_CERT"`
	TLSKey  string `yaml:"tls_key" env:"GADGET_TLS_KEY"`

	// Zone apex: NS and A/AAAA for delegation
	NSRecords []string `yaml:"ns_records" env:"GADGET_NS_RECORDS"`
	// ServerIPs are A/AAAA for zone apex (comma-separated in env)
	ServerIPs []net.IP `yaml:"server_ips" env:"-"`

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

	// Foreground (don't daemonize)
	Foreground bool `yaml:"foreground" env:"GADGET_FOREGROUND"`
}

// DefaultConfig returns defaults.
func DefaultConfig() Config {
	return Config{
		Domain:               "",
		UDPAddrs:             []string{":53"},
		TCPAddrs:             []string{":53"},
		DOTPort:              0,
		DOHPort:              0,
		DOQPort:              0,
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
		Foreground:           true,
	}
}

// Validate validates the config after merge.
func (c *Config) Validate() error {
	if c.ObtainCert {
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
	if (c.DOTPort > 0 || c.DOHPort > 0 || c.DOQPort > 0 || c.HTTPTLSPort > 0) && (c.TLSCert == "" || c.TLSKey == "") {
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
	if v := os.Getenv("GADGET_UDP_ADDRS"); v != "" {
		c.UDPAddrs = SplitTrim(v, ",")
	}
	if v := os.Getenv("GADGET_TCP_ADDRS"); v != "" {
		c.TCPAddrs = SplitTrim(v, ",")
	}
	if v := os.Getenv("GADGET_DOT_PORT"); v != "" {
		n, _ := strconv.Atoi(v)
		c.DOTPort = n
	}
	if v := os.Getenv("GADGET_DOH_PORT"); v != "" {
		n, _ := strconv.Atoi(v)
		c.DOHPort = n
	}
	if v := os.Getenv("GADGET_DOQ_PORT"); v != "" {
		n, _ := strconv.Atoi(v)
		c.DOQPort = n
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
		c.ServerIPs = ips
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
	return nil
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
