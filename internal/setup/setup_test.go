package setup

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/davidgroves/gadget-dns-server/internal/config"
	"github.com/davidgroves/gadget-dns-server/internal/dnssec"
	"github.com/davidgroves/gadget-dns-server/internal/handler"
	"github.com/miekg/dns"
)

func TestNewSignerFromConfig_Disabled(t *testing.T) {
	cfg := &config.Config{Domain: "example.com"}
	signer, err := NewSignerFromConfig(cfg, false)
	if err != nil {
		t.Fatalf("NewSignerFromConfig: %v", err)
	}
	if signer != nil {
		t.Error("expected nil signer when DNSSEC disabled")
	}
}

func TestNewSignerFromConfig_NoPaths(t *testing.T) {
	cfg := &config.Config{Domain: "example.com", DNSSEC: true}
	signer, err := NewSignerFromConfig(cfg, false)
	if err != nil {
		t.Fatalf("NewSignerFromConfig: %v", err)
	}
	if signer != nil {
		t.Error("expected nil signer when key paths empty")
	}
}

func TestNewSignerFromConfig_WithKeys(t *testing.T) {
	dir := t.TempDir()
	zone := "example.com."
	ksk, err := dnssec.GenerateKeyPair(zone, dns.ECDSAP256SHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := dnssec.GenerateKeyPair(zone, dns.ECDSAP256SHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := dnssec.WriteKeyPair(ksk, filepath.Join(dir, "ksk")); err != nil {
		t.Fatal(err)
	}
	if err := dnssec.WriteKeyPair(zsk, filepath.Join(dir, "zsk")); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Domain:        "example.com",
		DNSSEC:        true,
		DNSSECKSKPath: filepath.Join(dir, "ksk"),
		DNSSECZSKPath: filepath.Join(dir, "zsk"),
	}
	signer, err := NewSignerFromConfig(cfg, false)
	if err != nil {
		t.Fatalf("NewSignerFromConfig: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestHandlerConfigFrom(t *testing.T) {
	cfg := &config.Config{
		Domain:     "example.com",
		NSRecords:  []string{"ns.example.com."},
		SOAMname:   "ns.example.com.",
		SOARname:   "hostmaster.example.com.",
		SOASerial:  1,
		SOARefresh: 86400,
		SOARetry:   7200,
		SOAExpire:  3600000,
		SOAMinttl:  60,
	}
	serverIPs := []net.IP{net.ParseIP("192.0.2.1")}
	hc := HandlerConfigFrom(cfg, serverIPs, nil, handler.Config{})
	if hc.Domain != "example.com" {
		t.Errorf("Domain=%q", hc.Domain)
	}
	if len(hc.NSRecords) != 1 || hc.NSRecords[0] != "ns.example.com." {
		t.Errorf("NSRecords=%v", hc.NSRecords)
	}
	if len(hc.ServerIPs) != 1 || !hc.ServerIPs[0].Equal(serverIPs[0]) {
		t.Errorf("ServerIPs=%v", hc.ServerIPs)
	}
}
