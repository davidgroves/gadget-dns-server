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
	"sync"
	"syscall"
	"time"

	"github.com/davidgroves/gadget-dns-server/internal/acme"
	"github.com/davidgroves/gadget-dns-server/internal/config"
	"github.com/davidgroves/gadget-dns-server/internal/dnssec"
	"github.com/davidgroves/gadget-dns-server/internal/handler"
	"github.com/davidgroves/gadget-dns-server/internal/httpapi"
	"github.com/davidgroves/gadget-dns-server/internal/logging"
	"github.com/davidgroves/gadget-dns-server/internal/metrics"
	"github.com/davidgroves/gadget-dns-server/internal/server"
	"github.com/davidgroves/gadget-dns-server/internal/setup"
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
	udpPort              = flag.Int("udp-port", 0, "UDP port (0=use config default)")
	tcpPort              = flag.Int("tcp-port", 0, "TCP port (0=use config default)")
	dotPort              = flag.Int("dot-port", 0, "DoT port (0=disabled)")
	dohPort              = flag.Int("doh-port", 0, "DoH port (0=disabled)")
	doqPort              = flag.Int("doq-port", 0, "DoQ port (0=disabled)")
	binds                = flag.String("bind", "", "comma-separated bind addresses (e.g. 0.0.0.0,::); empty=all")
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
	path := *configPath
	if path == "" {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, "etc", "config.yaml")
		}
	}
	if path != "" {
		if _, err := os.Stat(path); err != nil {
			if *configPath != "" {
				fmt.Fprintf(os.Stderr, "config: %v\n", err)
				os.Exit(1)
			}
			path = "" // skip load when default path is missing
		}
		if path != "" {
			if err := config.LoadYAML(&cfg, path); err != nil {
				if *configPath != "" {
					fmt.Fprintf(os.Stderr, "config: %v\n", err)
					os.Exit(1)
				}
			}
		}
	}
	if err := cfg.SetFromEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "config env: %v\n", err)
		os.Exit(1)
	}
	// CLI overrides (table-driven)
	for _, apply := range []func(){
		func() {
			if *domain != "" {
				cfg.Domain = *domain
			}
		},
		func() {
			if *udpPort != 0 {
				cfg.Ports.UDP = *udpPort
			}
		},
		func() {
			if *tcpPort != 0 {
				cfg.Ports.TCP = *tcpPort
			}
		},
		func() {
			if *dotPort != 0 {
				cfg.Ports.DoT = *dotPort
			}
		},
		func() {
			if *dohPort != 0 {
				cfg.Ports.DoH = *dohPort
			}
		},
		func() {
			if *doqPort != 0 {
				cfg.Ports.DoQ = *doqPort
			}
		},
		func() {
			if *binds != "" {
				cfg.Binds = config.SplitTrim(*binds, ",")
			}
		},
		func() {
			if *tlsCert != "" {
				cfg.TLSCert = *tlsCert
			}
		},
		func() {
			if *tlsKey != "" {
				cfg.TLSKey = *tlsKey
			}
		},
		func() {
			if *httpPort != 0 {
				cfg.HTTPPort = *httpPort
			}
		},
		func() {
			if *acmeDomains != "" {
				cfg.ACMEDomains = config.SplitTrim(*acmeDomains, ",")
			}
		},
		func() {
			if *acmeAccount != "" {
				cfg.ACMEAccountKey = *acmeAccount
			}
		},
		func() {
			if *acmeURL != "" {
				cfg.ACMEURL = *acmeURL
			}
		},
		func() {
			if *logLevel != "" {
				cfg.LogLevel = *logLevel
			}
		},
		func() {
			if *obtainCert {
				cfg.ObtainCert = true
			}
		},
		func() {
			if *dnssecEnable {
				cfg.DNSSEC = true
			}
		},
		func() {
			if *dnssecKSK != "" {
				cfg.DNSSECKSKPath = *dnssecKSK
			}
		},
		func() {
			if *dnssecZSK != "" {
				cfg.DNSSECZSKPath = *dnssecZSK
			}
		},
		func() {
			if *dnssecRRSIGInception != "" {
				cfg.DNSSECRRSIGInception = *dnssecRRSIGInception
			}
		},
		func() {
			if *dnssecRRSIGValidity != "" {
				cfg.DNSSECRRSIGValidity = *dnssecRRSIGValidity
			}
		},
	} {
		apply()
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
		if err := cfg.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "obtain-cert: %v (set domain, acme_domains and tls_cert/tls_key in config or use CLI flags)\n", err)
			os.Exit(1)
		}
		// Start DNS first so Let's Encrypt can resolve our names (e.g. diag.<zone>).
		// Then start HTTP on port 80 for ACME HTTP-01. No TLS listeners (we don't have certs yet).
		obtainSigner, err := setup.NewSignerFromConfig(&cfg, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "obtain-cert load signer: %v\n", err)
			os.Exit(1)
		}
		serverIPs, err := cfg.EffectiveServerIPs()
		if err != nil {
			logging.Warn("obtain-cert: could not derive server IPs, apex/www/diag A/AAAA may be missing", "err", err)
		}
		obtainHandler := handler.New(setup.HandlerConfigFrom(&cfg, serverIPs, obtainSigner, handler.Config{Version: getVersion()}))
		obtainDNS := server.New(server.Config{
			Handler:         obtainHandler,
			UDPAddrs:        cfg.UDPAddrs(),
			TCPAddrs:        cfg.TCPAddrs(),
			DOTAddrs:        nil,
			DOHAddrs:        nil,
			DOQAddrs:        nil,
			TLSCert:         "",
			TLSKey:          "",
			MetricsRecorder: nil,
		})
		if err := obtainDNS.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "obtain-cert DNS: %v\n", err)
			os.Exit(1)
		}
		defer obtainDNS.Close()
		acmeResp := httpapi.NewACMEResponder()
		routes := httpapi.NewRoutes(acmeResp, httpapi.NewFeed(100))
		srv := httpapi.NewServer(cfg.HTTPPort, routes)
		if err := srv.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "http server: %v\n", err)
			fmt.Fprintf(os.Stderr, "obtain-cert needs port %d for ACME HTTP-01; stop any service using it and retry.\n", cfg.HTTPPort)
			os.Exit(1)
		}
		time.Sleep(500 * time.Millisecond)
		logging.Info("obtain-cert: DNS and HTTP up; running ACME", "domain", cfg.Domain)
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

	signer, err := setup.NewSignerFromConfig(&cfg, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load signer: %v\n", err)
		os.Exit(1)
	}

	serverIPs, err := cfg.EffectiveServerIPs()
	if err != nil {
		logging.Warn("could not derive server IPs from binds/interfaces, apex/www/diag will have no A/AAAA", "err", err)
	}
	diagRetention := config.ParseDiagRetention(cfg.DiagRetention)
	diagStore := httpapi.NewDiagStore(100, diagRetention)
	diagRecorder := &diagRecorderAdapter{store: diagStore}

	entropyStore := httpapi.NewEntropyStore(100, 10*time.Minute, httpapi.EntropyNSamples)
	entropyRecorder := &entropyRecorderAdapter{store: entropyStore}

	qnameMinStore := handler.NewQnameMinStore(60*time.Second, 50)

	metricsRecorder := metrics.NewRecorder()
	h := handler.New(setup.HandlerConfigFrom(&cfg, serverIPs, signer, handler.Config{
		Version:          getVersion(),
		DiagRecorder:     diagRecorder,
		EntropyRecorder:  entropyRecorder,
		QnameMinRecorder: qnameMinStore,
		MetricsRecorder:  metricsRecorder,
	}))

	feed := httpapi.NewFeed(1000)
	acmeResp := httpapi.NewACMEResponder()
	routes := httpapi.NewRoutes(acmeResp, feed)
	routes.DiagStore = diagStore
	routes.DiagDomain = cfg.Domain
	routes.EntropyStore = entropyStore
	routes.Version = getVersion()
	// When DoH port equals HTTP TLS port, serve DoH on the same server (avoid binding 443 twice)
	dohAddrs := cfg.DOHAddrs()
	if cfg.Ports.DoH == cfg.HTTPTLSPort && cfg.HTTPTLSPort > 0 && cfg.TLSCert != "" && cfg.TLSKey != "" {
		routes.DoHHandler = server.DoHHandler(h, metricsRecorder)
		dohAddrs = nil
	}
	httpSrv := httpapi.NewServer(cfg.HTTPPort, routes)
	httpSrv.TLSPort = cfg.HTTPTLSPort
	httpSrv.TLSCert = cfg.TLSCert
	httpSrv.TLSKey = cfg.TLSKey
	if err := httpSrv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "http server: %v\n", err)
		os.Exit(1)
	}

	dnsSrv := server.New(server.Config{
		Handler:         h,
		UDPAddrs:        cfg.UDPAddrs(),
		TCPAddrs:        cfg.TCPAddrs(),
		DOTAddrs:        cfg.DOTAddrs(),
		DOHAddrs:        dohAddrs,
		DOQAddrs:        cfg.DOQAddrs(),
		TLSCert:         cfg.TLSCert,
		TLSKey:          cfg.TLSKey,
		MetricsRecorder: metricsRecorder,
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

// diagSessionTTL is how long a client is considered "in diag session" after a token.diag query (for attaching related queries).
const diagSessionTTL = 30 * time.Second

type diagSessionEntry struct {
	token string
	until time.Time
}

// diagRecorderAdapter implements handler.DiagRecorder and handler.RelatedRecorder by pushing to httpapi.DiagStore.
type diagRecorderAdapter struct {
	store   *httpapi.DiagStore
	mu      sync.Mutex
	session map[string]diagSessionEntry // clientAddr -> token + expiry
}

func (a *diagRecorderAdapter) RecordDiag(token string, req *dns.Msg, resp *dns.Msg, clientAddr string, transport string) {
	var qname, qtypeStr string
	if len(req.Question) > 0 {
		q := req.Question[0]
		qname = q.Name
		qtypeStr = dns.TypeToString[q.Qtype]
		if qtypeStr == "" {
			qtypeStr = fmt.Sprintf("TYPE%d", q.Qtype)
		}
	}
	var reqWire, respWire []byte
	if req != nil {
		reqWire, _ = req.Pack()
	}
	if resp != nil {
		respWire, _ = resp.Pack()
	}
	a.store.Record(token, httpapi.Event{
		Qname:        qname,
		Qtype:        qtypeStr,
		ClientAddr:   clientAddr,
		Transport:    transport,
		RequestWire:  reqWire,
		ResponseWire: respWire,
	})
	a.mu.Lock()
	if a.session == nil {
		a.session = make(map[string]diagSessionEntry)
	}
	a.session[clientAddr] = diagSessionEntry{token: token, until: time.Now().Add(diagSessionTTL)}
	a.mu.Unlock()
}

func (a *diagRecorderAdapter) RecordRelatedIfInSession(clientAddr string, req *dns.Msg, resp *dns.Msg, transport string) {
	a.mu.Lock()
	ent, ok := a.session[clientAddr]
	now := time.Now()
	if !ok || now.After(ent.until) {
		if ok {
			delete(a.session, clientAddr)
		}
		a.mu.Unlock()
		return
	}
	token := ent.token
	a.mu.Unlock()

	var qname, qtypeStr string
	if len(req.Question) > 0 {
		q := req.Question[0]
		qname = q.Name
		qtypeStr = dns.TypeToString[q.Qtype]
		if qtypeStr == "" {
			qtypeStr = fmt.Sprintf("TYPE%d", q.Qtype)
		}
	}
	var reqWire, respWire []byte
	if req != nil {
		reqWire, _ = req.Pack()
	}
	if resp != nil {
		respWire, _ = resp.Pack()
	}
	a.store.AppendRelated(token, clientAddr, httpapi.Event{
		Qname:        qname,
		Qtype:        qtypeStr,
		ClientAddr:   clientAddr,
		Transport:    transport,
		RequestWire:  reqWire,
		ResponseWire: respWire,
	})
}

// entropyRecorderAdapter implements handler.EntropyRecorder by recording to httpapi.EntropyStore.
type entropyRecorderAdapter struct {
	store *httpapi.EntropyStore
}

func (a *entropyRecorderAdapter) RecordEntropy(runId string, clientAddr string, sourcePort int, transactionID uint16, qname string) {
	a.store.Record(runId, sourcePort, transactionID, qname)
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
