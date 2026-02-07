package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/davidgroves/gadget-dns-server/internal/acme"
	"github.com/davidgroves/gadget-dns-server/internal/config"
	"github.com/davidgroves/gadget-dns-server/internal/dnssec"
	"github.com/davidgroves/gadget-dns-server/internal/handler"
	"github.com/davidgroves/gadget-dns-server/internal/httpapi"
	"github.com/davidgroves/gadget-dns-server/internal/logging"
	"github.com/davidgroves/gadget-dns-server/internal/server"
	"github.com/miekg/dns"
)

// version is set at build time via -ldflags "-X main.version=..."
var versionStr string

func getVersion() string {
	if versionStr != "" {
		return versionStr
	}
	dir, err := findGitRoot()
	if err != nil {
		return "unknown"
	}
	tag, err := exec.Command("git", "-C", dir, "describe", "--tags", "--exact-match", "HEAD").Output()
	if err == nil {
		return strings.TrimSpace(string(tag))
	}
	hash, err := exec.Command("git", "-C", dir, "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return fmt.Sprintf("%s-%s", time.Now().Format("20060102"), strings.TrimSpace(string(hash)))
}

func findGitRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("not in a git repo")
		}
		dir = parent
	}
}

var (
	obtainCert           = flag.Bool("obtain-cert", false, "obtain ACME certificate and exit")
	configPath           = flag.String("config", "", "path to YAML config file")
	domain               = flag.String("domain", "", "zone domain (required for server)")
	udpAddrs             = flag.String("udp", ":53", "comma-separated UDP listen addresses")
	tcpAddrs             = flag.String("tcp", "", "comma-separated TCP listen addresses (default: same as udp)")
	dotPort              = flag.Int("dot-port", 0, "DoT port (0=disabled)")
	dohPort              = flag.Int("doh-port", 0, "DoH port (0=disabled)")
	doqPort              = flag.Int("doq-port", 0, "DoQ port (0=disabled)")
	tlsCert              = flag.String("tls-cert", "", "TLS certificate file")
	tlsKey               = flag.String("tls-key", "", "TLS key file")
	httpPort             = flag.Int("http-port", 80, "HTTP port for ACME/health/metrics/feed")
	acmeDomains          = flag.String("acme-domain", "", "comma-separated domains for ACME")
	acmeAccount          = flag.String("acme-account-key", "", "ACME account key path")
	acmeURL              = flag.String("acme-url", "", "ACME directory URL")
	logLevel             = flag.String("log-level", "info", "log level: debug, info, warn, error")
	dnssecEnable         = flag.Bool("dnssec", false, "enable DNSSEC signing")
	dnssecKSK            = flag.String("dnssec-ksk", "", "path to KSK key (prefix for .key/.private)")
	dnssecZSK            = flag.String("dnssec-zsk", "", "path to ZSK key (prefix for .key/.private)")
	dnssecRRSIGInception = flag.String("dnssec-rrsig-inception", "", "RRSIG inception offset (e.g. 1h); default 1h")
	dnssecRRSIGValidity  = flag.String("dnssec-rrsig-validity", "", "RRSIG validity duration (e.g. 24h); default 24h")
	genKeys              = flag.Bool("generate-zone-keys", false, "generate KSK and ZSK and exit")
	showVersion          = flag.Bool("version", false, "print version and exit")
)

func main() {
	flag.Parse()
	if *showVersion {
		fmt.Println(getVersion())
		os.Exit(0)
	}

	cfg := config.DefaultConfig()
	if *configPath != "" {
		if err := config.LoadYAML(&cfg, *configPath); err != nil {
			fmt.Fprintf(os.Stderr, "config: %v\n", err)
			os.Exit(1)
		}
	}
	if err := cfg.SetFromEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "config env: %v\n", err)
		os.Exit(1)
	}
	// CLI overrides
	if *domain != "" {
		cfg.Domain = *domain
	}
	if *udpAddrs != "" {
		cfg.UDPAddrs = config.SplitTrim(*udpAddrs, ",")
	}
	if *tcpAddrs != "" {
		cfg.TCPAddrs = config.SplitTrim(*tcpAddrs, ",")
	} else if *udpAddrs != "" {
		cfg.TCPAddrs = config.SplitTrim(*udpAddrs, ",")
	}
	if *dotPort != 0 {
		cfg.DOTPort = *dotPort
	}
	if *dohPort != 0 {
		cfg.DOHPort = *dohPort
	}
	if *doqPort != 0 {
		cfg.DOQPort = *doqPort
	}
	if *tlsCert != "" {
		cfg.TLSCert = *tlsCert
	}
	if *tlsKey != "" {
		cfg.TLSKey = *tlsKey
	}
	if *httpPort != 0 {
		cfg.HTTPPort = *httpPort
	}
	if *acmeDomains != "" {
		cfg.ACMEDomains = config.SplitTrim(*acmeDomains, ",")
	}
	if *acmeAccount != "" {
		cfg.ACMEAccountKey = *acmeAccount
	}
	if *acmeURL != "" {
		cfg.ACMEURL = *acmeURL
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}
	if *obtainCert {
		cfg.ObtainCert = true
	}
	if *dnssecEnable {
		cfg.DNSSEC = true
	}
	if *dnssecKSK != "" {
		cfg.DNSSECKSKPath = *dnssecKSK
	}
	if *dnssecZSK != "" {
		cfg.DNSSECZSKPath = *dnssecZSK
	}
	if *dnssecRRSIGInception != "" {
		cfg.DNSSECRRSIGInception = *dnssecRRSIGInception
	}
	if *dnssecRRSIGValidity != "" {
		cfg.DNSSECRRSIGValidity = *dnssecRRSIGValidity
	}

	level, _ := logging.ParseLevel(cfg.LogLevel)
	logging.Init(level, os.Stdout)

	if *genKeys {
		if cfg.Domain == "" || *dnssecKSK == "" || *dnssecZSK == "" {
			fmt.Fprintf(os.Stderr, "generate-zone-keys requires --domain, --dnssec-ksk, --dnssec-zsk\n")
			os.Exit(1)
		}
		zone := dns.Fqdn(cfg.Domain)
		for _, alg := range []uint8{dns.ECDSAP256SHA256, dns.RSASHA256, dns.ED25519} {
			ksk, err := dnssec.GenerateKeyPair(zone, alg, true)
			if err != nil {
				continue
			}
			zsk, err := dnssec.GenerateKeyPair(zone, alg, false)
			if err != nil {
				continue
			}
			if err := dnssec.WriteKeyPair(ksk, *dnssecKSK); err != nil {
				fmt.Fprintf(os.Stderr, "write KSK: %v\n", err)
				os.Exit(1)
			}
			if err := dnssec.WriteKeyPair(zsk, *dnssecZSK); err != nil {
				fmt.Fprintf(os.Stderr, "write ZSK: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Generated %s keys: KSK %s, ZSK %s\n", dns.AlgorithmToString[alg], *dnssecKSK, *dnssecZSK)
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "failed to generate keys\n")
		os.Exit(1)
	}

	if cfg.ObtainCert {
		acmeResp := httpapi.NewACMEResponder()
		routes := httpapi.NewRoutes(acmeResp, httpapi.NewFeed(100))
		srv := httpapi.NewServer(cfg.HTTPPort, routes)
		srv.TLSPort = cfg.HTTPTLSPort
		srv.TLSCert = cfg.TLSCert
		srv.TLSKey = cfg.TLSKey
		if err := srv.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "http server: %v\n", err)
			os.Exit(1)
		}
		time.Sleep(500 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := acme.Obtain(ctx, acme.ObtainConfig{
			Domains:          cfg.ACMEDomains,
			ACMEDirectoryURL: cfg.ACMEURL,
			AccountKeyPath:   cfg.ACMEAccountKey,
			CertOutputPath:   cfg.TLSCert,
			KeyOutputPath:    cfg.TLSKey,
			Responder:        acmeResp,
		}); err != nil {
			logging.Error("obtain-cert failed", "err", err)
			os.Exit(1)
		}
		return
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	var signer handler.Signer
	if cfg.DNSSEC && cfg.DNSSECKSKPath != "" && cfg.DNSSECZSKPath != "" {
		zone := dns.Fqdn(cfg.Domain)
		ksk, err := dnssec.LoadKeyPair(zone, cfg.DNSSECKSKPath, 0, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load KSK: %v\n", err)
			os.Exit(1)
		}
		zsk, err := dnssec.LoadKeyPair(zone, cfg.DNSSECZSKPath, 0, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load ZSK: %v\n", err)
			os.Exit(1)
		}
		inception := config.ParseRRSIGDuration(cfg.DNSSECRRSIGInception, time.Hour)
		validity := config.ParseRRSIGDuration(cfg.DNSSECRRSIGValidity, 24*time.Hour)
		signer = dnssec.NewSigner(cfg.Domain, ksk, zsk, dnssec.WithRRSIGValidity(inception, validity))
	}

	diagStore := httpapi.NewDiagStore(100)
	diagRecorder := &diagRecorderAdapter{store: diagStore}

	h := handler.New(handler.Config{
		Domain:       cfg.Domain,
		NSRecords:    cfg.NSRecords,
		ServerIPs:    cfg.ServerIPs,
		SOAMname:     cfg.SOAMname,
		SOARname:     cfg.SOARname,
		SOASerial:    cfg.SOASerial,
		SOARefresh:   cfg.SOARefresh,
		SOARetry:     cfg.SOARetry,
		SOAExpire:    cfg.SOAExpire,
		SOAMinttl:    cfg.SOAMinttl,
		Signer:       signer,
		DiagRecorder: diagRecorder,
	})

	feed := httpapi.NewFeed(1000)
	acmeResp := httpapi.NewACMEResponder()
	routes := httpapi.NewRoutes(acmeResp, feed)
	routes.DiagStore = diagStore
	routes.DiagDomain = cfg.Domain
	httpSrv := httpapi.NewServer(cfg.HTTPPort, routes)
	httpSrv.TLSPort = cfg.HTTPTLSPort
	httpSrv.TLSCert = cfg.TLSCert
	httpSrv.TLSKey = cfg.TLSKey
	if err := httpSrv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "http server: %v\n", err)
		os.Exit(1)
	}

	dnsSrv := server.New(server.Config{
		Handler:  h,
		UDPAddrs: cfg.UDPAddrs,
		TCPAddrs: cfg.TCPAddrs,
		DOTPort:  cfg.DOTPort,
		DOHPort:  cfg.DOHPort,
		DOQPort:  cfg.DOQPort,
		TLSCert:  cfg.TLSCert,
		TLSKey:   cfg.TLSKey,
	})
	if err := dnsSrv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "dns server: %v\n", err)
		os.Exit(1)
	}

	if cfg.TLSCert != "" && cfg.TLSKey != "" && len(cfg.ACMEDomains) > 0 && cfg.ACMERenewDays > 0 {
		go runRenewal(cfg, acmeResp)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logging.Info("shutting down")
	dnsSrv.Close()
}

// diagRecorderAdapter implements handler.DiagRecorder by pushing to httpapi.DiagStore.
type diagRecorderAdapter struct {
	store *httpapi.DiagStore
}

func (a *diagRecorderAdapter) RecordDiag(token string, qname string, qtype uint16, clientAddr string, transport string) {
	qtypeStr := dns.TypeToString[qtype]
	if qtypeStr == "" {
		qtypeStr = fmt.Sprintf("TYPE%d", qtype)
	}
	a.store.Record(token, httpapi.Event{
		Qname:      qname,
		Qtype:      qtypeStr,
		ClientAddr: clientAddr,
		Transport:  transport,
	})
}

func runRenewal(cfg config.Config, responder *httpapi.ACMEResponder) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		expiry, err := acme.CertExpiry(cfg.TLSCert)
		if err != nil {
			continue
		}
		daysLeft := time.Until(expiry).Hours() / 24
		if daysLeft > float64(cfg.ACMERenewDays) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		err = acme.Obtain(ctx, acme.ObtainConfig{
			Domains:          cfg.ACMEDomains,
			ACMEDirectoryURL: cfg.ACMEURL,
			AccountKeyPath:   cfg.ACMEAccountKey,
			CertOutputPath:   cfg.TLSCert,
			KeyOutputPath:    cfg.TLSKey,
			Responder:        responder,
		})
		cancel()
		if err != nil {
			logging.Error("ACME renewal failed", "err", err)
			continue
		}
		logging.Info("ACME certificate renewed")
	}
}
