package setup

import (
	"fmt"
	"net"
	"time"

	"github.com/davidgroves/gadget-dns-server/internal/config"
	"github.com/davidgroves/gadget-dns-server/internal/dnssec"
	"github.com/davidgroves/gadget-dns-server/internal/handler"
	"github.com/davidgroves/gadget-dns-server/internal/logging"
	"github.com/miekg/dns"
)

// NewSignerFromConfig builds a DNSSEC signer from cfg. Returns (nil, nil) when DNSSEC is disabled or key paths are empty.
// Caller can pass logCDS true to log the CDS record when publish CDS is set.
func NewSignerFromConfig(cfg *config.Config, logCDS bool) (handler.Signer, error) {
	if !cfg.DNSSEC || cfg.DNSSECKSKPath == "" || cfg.DNSSECZSKPath == "" {
		return nil, nil
	}
	zone := dns.Fqdn(cfg.Domain)
	ksk, err := dnssec.LoadKeyPair(zone, cfg.DNSSECKSKPath, 0, true)
	if err != nil {
		return nil, fmt.Errorf("load KSK: %w", err)
	}
	zsk, err := dnssec.LoadKeyPair(zone, cfg.DNSSECZSKPath, 0, false)
	if err != nil {
		return nil, fmt.Errorf("load ZSK: %w", err)
	}
	inception := config.ParseRRSIGDuration(cfg.DNSSECRRSIGInception, time.Hour)
	validity := config.ParseRRSIGDuration(cfg.DNSSECRRSIGValidity, 24*time.Hour)
	s := dnssec.NewSigner(cfg.Domain, ksk, zsk, dnssec.WithRRSIGValidity(inception, validity))
	if logCDS && cfg.DNSSECPublishCDS {
		if r := s.CDSRecord(); r != nil {
			logging.Info("parent DS must match CDS (KSK)", "key_tag", r.KeyTag, "algorithm", r.Algorithm, "digest_type", r.DigestType)
		}
	}
	return s, nil
}

// HandlerConfigFrom builds handler.Config from cfg, serverIPs, and signer. Overrides is applied after: any non-zero field in overrides replaces the value from cfg.
func HandlerConfigFrom(cfg *config.Config, serverIPs []net.IP, signer handler.Signer, overrides handler.Config) handler.Config {
	hc := handler.Config{
		Domain:           cfg.Domain,
		Hostname:         cfg.Hostname,
		Version:          overrides.Version,
		NSRecords:        cfg.NSRecords,
		ServerIPs:        serverIPs,
		SOAMname:         cfg.SOAMname,
		SOARname:         cfg.SOARname,
		SOASerial:        cfg.SOASerial,
		SOARefresh:       cfg.SOARefresh,
		SOARetry:         cfg.SOARetry,
		SOAExpire:        cfg.SOAExpire,
		SOAMinttl:        cfg.SOAMinttl,
		Signer:           signer,
		PublishCDS:       cfg.DNSSECPublishCDS,
		DiagRecorder:     overrides.DiagRecorder,
		EntropyRecorder:  overrides.EntropyRecorder,
		QnameMinRecorder: overrides.QnameMinRecorder,
		MetricsRecorder:  overrides.MetricsRecorder,
	}
	return hc
}
