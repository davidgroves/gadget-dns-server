package dnssec

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/davidgroves/gadget-dns-server/internal/handler"
	"github.com/miekg/dns"
)

func TestSigner_SignResponse_SOA(t *testing.T) {
	dir := t.TempDir()
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	_ = WriteKeyPair(ksk, filepath.Join(dir, "ksk"))
	_ = WriteKeyPair(zsk, filepath.Join(dir, "zsk"))

	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{
		Domain: "example.com",
		Signer: signer,
	})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeSOA)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	// Should have SOA + RRSIG
	var hasSOA, hasRRSIG bool
	for _, rr := range msg.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeSOA:
			hasSOA = true
		case dns.TypeRRSIG:
			hasRRSIG = true
		}
	}
	if !hasSOA {
		t.Error("missing SOA in answer")
	}
	if !hasRRSIG {
		t.Error("missing RRSIG in answer")
	}
}

func TestSigner_SignResponse_NXDOMAIN_NSEC(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{
		Domain: "example.com",
		Signer: signer,
	})

	req := new(dns.Msg)
	req.SetQuestion("nonexistent.example.com.", dns.TypeA)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode=%d want NXDOMAIN", msg.Rcode)
	}
	var hasNSEC, hasRRSIG bool
	for _, rr := range msg.Ns {
		switch rr.Header().Rrtype {
		case dns.TypeNSEC:
			hasNSEC = true
		case dns.TypeRRSIG:
			hasRRSIG = true
		}
	}
	if !hasNSEC {
		t.Error("missing NSEC for NXDOMAIN")
	}
	if !hasRRSIG {
		t.Error("missing RRSIG for NSEC")
	}
}

func TestSigner_SignResponse_NXDOMAIN_Direct(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	msg := new(dns.Msg)
	msg.SetQuestion("nonexistent.example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{}
	err := signer.SignResponse(msg, "nonexistent.example.com.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	var hasNSEC, hasRRSIG bool
	for _, rr := range msg.Ns {
		switch rr.Header().Rrtype {
		case dns.TypeNSEC:
			hasNSEC = true
		case dns.TypeRRSIG:
			hasRRSIG = true
		}
	}
	if !hasNSEC {
		t.Error("missing NSEC")
	}
	if !hasRRSIG {
		t.Errorf("missing RRSIG; msg.Ns has %d RRs", len(msg.Ns))
	}
}

func TestSigner_WithRRSIGValidity(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	// 1h inception, 1h validity
	signer := NewSigner("example.com", ksk, zsk, WithRRSIGValidity(time.Hour, time.Hour))
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeSOA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = append(msg.Answer, &dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:     "example.com.",
		Mbox:   "hostmaster.example.com.",
		Serial: 1, Refresh: 86400, Retry: 7200, Expire: 3600000, Minttl: 60,
	})
	err := signer.SignResponse(msg, "example.com.", dns.TypeSOA)
	if err != nil {
		t.Fatal(err)
	}
	var rrsig *dns.RRSIG
	for _, rr := range msg.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			rrsig = sig
			break
		}
	}
	if rrsig == nil {
		t.Fatal("no RRSIG in answer")
	}
	validity := rrsig.Expiration - rrsig.Inception
	// Inception = now-1h, expiration = now+1h => 2h window
	if validity < 7100 || validity > 7300 {
		t.Errorf("RRSIG validity = %d sec, want ~7200 (2h)", validity)
	}
}

func TestSigner_CDSRecord(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	cds := signer.CDSRecord()
	if cds == nil {
		t.Fatal("CDS record nil")
	}
	if cds.KeyTag != ksk.DNSKEY.KeyTag() {
		t.Errorf("CDS KeyTag=%d want %d", cds.KeyTag, ksk.DNSKEY.KeyTag())
	}
}
