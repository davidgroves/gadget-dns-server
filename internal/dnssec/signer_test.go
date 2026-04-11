package dnssec

import (
	"net"
	"path/filepath"
	"strings"
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
	req.SetEdns0(4096, true) // DO bit so signer adds RRSIG
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
	req.SetEdns0(4096, true) // DO bit so signer adds NSEC/RRSIG
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
	req := new(dns.Msg)
	req.SetQuestion("nonexistent.example.com.", dns.TypeA)
	req.SetEdns0(4096, true) // DO bit so signer adds NSEC/RRSIG
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.SetQuestion("nonexistent.example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{}
	err := signer.SignResponse(msg, req)
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

// TestSigner_SignResponse_NXDOMAIN_WildcardCover verifies RFC 4035 §3.1.3.2: NXDOMAIN response
// includes an NSEC that covers the wildcard (*.<zone>) so validators can prove no wildcard match.
func TestSigner_SignResponse_NXDOMAIN_WildcardCover(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	req := new(dns.Msg)
	req.SetQuestion("tp49w.nkmra.example.com.", dns.TypeA)
	req.SetEdns0(4096, true)
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.SetQuestion("tp49w.nkmra.example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{}
	err := signer.SignResponse(msg, req)
	if err != nil {
		t.Fatal(err)
	}
	wildcardFQDN := "*.example.com."
	var foundWildcardNSEC bool
	for _, rr := range msg.Ns {
		nsec, ok := rr.(*dns.NSEC)
		if !ok {
			continue
		}
		// RFC 4035 §3.1.3.2: need an NSEC where owner < *.zone < next
		if nsec.Hdr.Name < wildcardFQDN && wildcardFQDN < nsec.NextDomain {
			foundWildcardNSEC = true
			break
		}
	}
	if !foundWildcardNSEC {
		t.Error("NXDOMAIN response must include an NSEC that covers the wildcard (*.example.com.); see RFC 4035 §3.1.3.2")
	}
}

// TestSigner_SignResponse_NXDOMAIN_SnameCover verifies RFC 4035 §3.1.3.2: NXDOMAIN response
// includes an NSEC that covers the SNAME (qname) in canonical order so validators accept the proof.
func TestSigner_SignResponse_NXDOMAIN_SnameCover(t *testing.T) {
	ksk, _ := GenerateKeyPair("dnssrc.fibrecat.org.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("dnssrc.fibrecat.org.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("dnssrc.fibrecat.org", ksk, zsk)
	req := new(dns.Msg)
	qname := "ixcuh.pq2ws.dnssrc.fibrecat.org."
	req.SetQuestion(qname, dns.TypeA)
	req.SetEdns0(4096, true)
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{}
	err := signer.SignResponse(msg, req)
	if err != nil {
		t.Fatal(err)
	}
	// Validator checks: some NSEC (owner, next) must satisfy owner < qname < next in canonical order.
	var foundCover bool
	for _, rr := range msg.Ns {
		nsec, ok := rr.(*dns.NSEC)
		if !ok {
			continue
		}
		if dnsCanonicalLess(nsec.Hdr.Name, qname) && dnsCanonicalLess(qname, nsec.NextDomain) {
			foundCover = true
			break
		}
	}
	if !foundCover {
		t.Error("NXDOMAIN response must include an NSEC that covers the SNAME (ixcuh.pq2ws.dnssrc.fibrecat.org.) in canonical order; see RFC 4035 §3.1.3.2")
	}
}

// TestSigner_SignResponse_NXDOMAIN_zzzzz exercises the path where qname sorts after the last
// name in the zone (single NSEC(last, apex)); also packs the message to catch any wire-format panic.
func TestSigner_SignResponse_NXDOMAIN_zzzzz(t *testing.T) {
	ksk, _ := GenerateKeyPair("dnssrc.fibrecat.org.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("dnssrc.fibrecat.org.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("dnssrc.fibrecat.org", ksk, zsk)
	h := handler.New(handler.Config{Domain: "dnssrc.fibrecat.org", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("zzzzz.dnssrc.fibrecat.org.", dns.TypeTXT)
	req.SetEdns0(4096, true) // DO bit so signer adds NSEC/RRSIG
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg == nil {
		t.Fatal("Handle returned nil")
	}
	if msg.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode=%d want NXDOMAIN", msg.Rcode)
	}
	// Pack to wire format (can panic if any RR is invalid)
	_, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
}

// TestSigner_SignResponse_delay10_A_NODATA verifies that delay-10 A (NODATA) with DNSSEC
// returns NOERROR and a name-exists NSEC (owner=delay-10..., TypeBitMap includes TXT only),
// not NXDOMAIN-style NSEC which would cause validators to return SERVFAIL (EDE 6 DNSSEC Bogus).
func TestSigner_SignResponse_delay10_A_NODATA(t *testing.T) {
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
	req.SetQuestion("delay-10.example.com.", dns.TypeA)
	req.SetEdns0(4096, true) // DO bit so signer adds NSEC
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("delay-10 A: rcode=%d want NOERROR", msg.Rcode)
	}
	if len(msg.Answer) != 0 {
		t.Fatalf("delay-10 A: NODATA should have no Answer, got %d", len(msg.Answer))
	}
	var nsecOwner string
	for _, rr := range msg.Ns {
		if nsec, ok := rr.(*dns.NSEC); ok {
			nsecOwner = nsec.Hdr.Name
			// NODATA NSEC must be for the qname (name exists), not a gap
			if nsec.Hdr.Name != "delay-10.example.com." {
				t.Errorf("NODATA NSEC owner=%q want delay-10.example.com. (name-exists NSEC)", nsec.Hdr.Name)
			}
			// TypeBitMap for delay-* is TXT only; qtype A excluded so bitmap should contain TXT
			hasTXT := false
			for _, t := range nsec.TypeBitMap {
				if t == dns.TypeTXT {
					hasTXT = true
					break
				}
			}
			if !hasTXT {
				t.Errorf("NODATA NSEC TypeBitMap should include TXT for delay-10, got %v", nsec.TypeBitMap)
			}
			break
		}
	}
	if nsecOwner == "" {
		t.Error("missing NSEC in NODATA response")
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
	err := signer.SignResponse(msg, nil)
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

// TestSigner_CDSRecord_uses_zone_name verifies that the CDS digest is computed using
// the signer's zone name, not the key file's owner. If the key was generated for
// a different zone, NewSigner overwrites DNSKEY.Hdr.Name so CDS/DS validates.
func TestSigner_CDSRecord_uses_zone_name(t *testing.T) {
	// Key generated for "other.com" but we use signer for "example.com"
	ksk, _ := GenerateKeyPair("other.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("other.com.", dns.ECDSAP256SHA256, false)
	digestForOtherCom := ksk.DNSKEY.ToDS(dns.SHA256)
	if digestForOtherCom == nil {
		t.Fatal("ToDS returned nil")
	}
	signer := NewSigner("example.com", ksk, zsk)
	cds := signer.CDSRecord()
	if cds == nil {
		t.Fatal("CDS record nil")
	}
	// Digest must be for "example.com." (signer's zone), not "other.com."
	if cds.Digest == digestForOtherCom.Digest {
		t.Error("CDS digest must differ when signer zone differs from key owner; got same digest")
	}
	// CDS digest must match ToDS with signer's zone name
	if cds.Digest != ksk.DNSKEY.ToDS(dns.SHA256).Digest {
		t.Error("CDS digest should match signer zone (NewSigner sets DNSKEY.Hdr.Name)")
	}
}

// TestSigner_SignResponse_noDO_noRRSIG verifies that when the request has no EDNS DO bit,
// the signer does not add RRSIG or NSEC (only adds DNSKEY to Answer when qtype is DNSKEY).
func TestSigner_SignResponse_noDO_noRRSIG(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("myip.example.com.", dns.TypeTXT)
	// No SetEdns0 or SetEdns0(4096, false) — DO bit not set
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			t.Error("expected no RRSIG in answer when DO bit not set")
			break
		}
	}
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == dns.TypeNSEC || rr.Header().Rrtype == dns.TypeRRSIG {
			t.Error("expected no NSEC/RRSIG in Ns when DO bit not set")
			break
		}
	}
}

// DNSSEC fail-case tests: each label deliberately breaks validation so validators get SERVFAIL.

func TestSigner_SignResponse_rrsig_expired(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("rrsig-expired.dnssec-failed.example.com.", dns.TypeA)
	req.SetEdns0(4096, true) // DO bit so signer adds RRSIG
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	now := uint32(time.Now().UTC().Unix())
	for _, rr := range msg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			if rrsig.Expiration >= now || rrsig.Inception >= now {
				t.Errorf("rrsig-expired: RRSIG should be in the past; Inception=%d Expiration=%d now=%d", rrsig.Inception, rrsig.Expiration, now)
			}
			return
		}
	}
	t.Error("no RRSIG in answer for rrsig-expired")
}

// Mixed-case qname (resolver 0x20); owner names echo wire case — signer must still apply fail-case RRSIG windows.
func TestSigner_SignResponse_rrsig_expired_mixedCaseQname(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("RrSiG-ExPiReD.DnSsEc-FaIlEd.ExAmPlE.CoM.", dns.TypeA)
	req.SetEdns0(4096, true)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	now := uint32(time.Now().UTC().Unix())
	for _, rr := range msg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			if rrsig.Expiration >= now || rrsig.Inception >= now {
				t.Errorf("rrsig-expired (mixed-case qname): RRSIG should be in the past; Inception=%d Expiration=%d now=%d", rrsig.Inception, rrsig.Expiration, now)
			}
			return
		}
	}
	t.Error("no RRSIG in answer for rrsig-expired (mixed-case qname)")
}

func TestSigner_SignResponse_rrsig_future(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("rrsig-future.dnssec-failed.example.com.", dns.TypeA)
	req.SetEdns0(4096, true) // DO bit so signer adds RRSIG
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	now := uint32(time.Now().UTC().Unix())
	for _, rr := range msg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			if rrsig.Inception <= now || rrsig.Expiration <= now {
				t.Errorf("rrsig-future: RRSIG should be in the future; Inception=%d Expiration=%d now=%d", rrsig.Inception, rrsig.Expiration, now)
			}
			return
		}
	}
	t.Error("no RRSIG in answer for rrsig-future")
}

func TestSigner_SignResponse_rrsig_future_mixedCaseQname(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("RrSiG-FuTuRe.DnSsEc-FaIlEd.ExAmPlE.CoM.", dns.TypeA)
	req.SetEdns0(4096, true)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	now := uint32(time.Now().UTC().Unix())
	for _, rr := range msg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			if rrsig.Inception <= now || rrsig.Expiration <= now {
				t.Errorf("rrsig-future (mixed-case qname): RRSIG should be in the future; Inception=%d Expiration=%d now=%d", rrsig.Inception, rrsig.Expiration, now)
			}
			return
		}
	}
	t.Error("no RRSIG in answer for rrsig-future (mixed-case qname)")
}

func TestSigner_SignResponse_nsec_missing(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("nsec-missing.dnssec-failed.example.com.", dns.TypeA)
	req.SetEdns0(4096, true) // DO bit so signer runs (but skips NSEC for this fail-case)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == dns.TypeNSEC {
			t.Error("nsec-missing: should have no NSEC in Ns")
			break
		}
	}
}

func TestSigner_SignResponse_nsec_wrong_next(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("nsec-wrong-next.dnssec-failed.example.com.", dns.TypeA)
	req.SetEdns0(4096, true) // DO bit so signer adds NSEC
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	zoneApex := "example.com."
	for _, rr := range msg.Ns {
		if nsec, ok := rr.(*dns.NSEC); ok && nsec.Hdr.Name == "nsec-wrong-next.dnssec-failed.example.com." {
			if nsec.NextDomain == zoneApex {
				t.Errorf("nsec-wrong-next: NSEC NextDomain should not be zone apex %q", zoneApex)
			}
			return
		}
	}
	t.Error("no NSEC for nsec-wrong-next.dnssec-failed.example.com. in Ns")
}

func TestSigner_SignResponse_rrsig_wrong_alg(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("rrsig-wrong-alg.dnssec-failed.example.com.", dns.TypeA)
	req.SetEdns0(4096, true) // DO bit so signer adds RRSIG
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	for _, rr := range msg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			if rrsig.Algorithm == dns.ECDSAP256SHA256 {
				t.Errorf("rrsig-wrong-alg: RRSIG Algorithm should differ from zone key (13); got %d", rrsig.Algorithm)
			}
			return
		}
	}
	t.Error("no RRSIG in answer for rrsig-wrong-alg")
}

func TestSigner_SignResponse_rrsig_wrong_alg_mixedCaseQname(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("RrSiG-WrOnG-AlG.DnSsEc-FaIlEd.ExAmPlE.CoM.", dns.TypeA)
	req.SetEdns0(4096, true)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	for _, rr := range msg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			if rrsig.Algorithm == dns.ECDSAP256SHA256 {
				t.Errorf("rrsig-wrong-alg (mixed-case qname): RRSIG Algorithm should differ from zone key (13); got %d", rrsig.Algorithm)
			}
			return
		}
	}
	t.Error("no RRSIG in answer for rrsig-wrong-alg (mixed-case qname)")
}

func TestSigner_SignResponse_rrsig_missing(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("rrsig-missing.dnssec-failed.example.com.", dns.TypeA)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	owner := "rrsig-missing.dnssec-failed.example.com."
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeA && rr.Header().Name == owner {
			for _, r := range msg.Answer {
				if sig, ok := r.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeA && sig.Hdr.Name == owner {
					t.Error("rrsig-missing: should have no RRSIG covering the A RRset for this owner")
					return
				}
			}
			return // A present, no RRSIG for it
		}
	}
	t.Error("no A record for rrsig-missing in answer")
}

func TestSigner_SignResponse_rrsig_missing_mixedCaseQname(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("RrSiG-MiSsInG.DnSsEc-FaIlEd.ExAmPlE.CoM.", dns.TypeA)
	req.SetEdns0(4096, true)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	wantOwner := fqdnForCompare(req.Question[0].Name)
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeA && fqdnForCompare(rr.Header().Name) == wantOwner {
			for _, r := range msg.Answer {
				if sig, ok := r.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeA && fqdnForCompare(sig.Hdr.Name) == wantOwner {
					t.Error("rrsig-missing (mixed-case qname): should have no RRSIG covering the A RRset for this owner")
					return
				}
			}
			return
		}
	}
	t.Error("no A record for rrsig-missing in answer (mixed-case qname)")
}

func TestFqdnForCompare(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"ExAmPlE.CoM", "example.com."},
		{"eXaMpLe.CoM.", "example.com."},
		{"foo.BAR.example.com", "foo.bar.example.com."},
		{"rrsig-expired.dnssec-failed.example.com", "rrsig-expired.dnssec-failed.example.com."},
	}
	for _, tc := range tests {
		if got := fqdnForCompare(tc.in); got != tc.want {
			t.Errorf("fqdnForCompare(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func findAAndRRSIG(t *testing.T, msg *dns.Msg) (*dns.A, *dns.RRSIG) {
	t.Helper()
	var a *dns.A
	for _, rr := range msg.Answer {
		if x, ok := rr.(*dns.A); ok {
			a = x
			break
		}
	}
	if a == nil {
		t.Fatalf("missing A in answer (have %d RRs)", len(msg.Answer))
	}
	owner := fqdnForCompare(a.Hdr.Name)
	var sig *dns.RRSIG
	for _, rr := range msg.Answer {
		x, ok := rr.(*dns.RRSIG)
		if !ok || x.TypeCovered != dns.TypeA {
			continue
		}
		if fqdnForCompare(x.Hdr.Name) != owner {
			continue
		}
		sig = x
		break
	}
	if sig == nil {
		t.Fatalf("missing RRSIG(TypeA) for owner %q in answer (have %d RRs)", a.Hdr.Name, len(msg.Answer))
	}
	return a, sig
}

// rrsig-wrong-rrset signs a minimal apex SOA RRset (see signRRSetWithKey); miekg/dns Sign() overwrites
// RRSIG TypeCovered and owner from that rrset, so Answer holds A at the gadget plus an RRSIG over SOA at apex.
// Mixed-case qname must still take that branch (fqdnForCompare), not emit a normal TypeA RRSIG.
func assertRRSIGWrongRRsetGadget(t *testing.T, msg *dns.Msg, zsk *KeyPair) {
	t.Helper()
	var a *dns.A
	var rrsig *dns.RRSIG
	for _, rr := range msg.Answer {
		switch x := rr.(type) {
		case *dns.A:
			a = x
		case *dns.RRSIG:
			rrsig = x
		}
	}
	if a == nil || rrsig == nil {
		t.Fatalf("want A + RRSIG in answer, got A=%v RRSIG=%v (n=%d)", a != nil, rrsig != nil, len(msg.Answer))
	}
	if rrsig.TypeCovered != dns.TypeSOA {
		t.Fatalf("rrsig-wrong-rrset: RRSIG TypeCovered=%s want SOA (else gadget was signed as normal A RRset)",
			dns.TypeToString[rrsig.TypeCovered])
	}
	if fqdnForCompare(rrsig.Hdr.Name) != "example.com." {
		t.Fatalf("rrsig-wrong-rrset: RRSIG owner=%q want apex example.com.", rrsig.Hdr.Name)
	}
	soaSigned := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      ".",
		Mbox:    ".",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}
	if err := rrsig.Verify(zsk.DNSKEY, []dns.RR{soaSigned}); err != nil {
		t.Fatalf("RRSIG should verify over the SOA RRset it was signed with: %v", err)
	}
	if fqdnForCompare(a.Hdr.Name) == fqdnForCompare(rrsig.Hdr.Name) {
		t.Fatal("gadget A owner must differ from RRSIG owner (apex SOA signature)")
	}
}

// DNS 0x20 / mixed-case qname must still trigger rrsig-wrong-rrset (signature over wrong RRset).
func TestSigner_SignResponse_rrsig_wrong_rrset_mixedCaseQname(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("RrSiG-WrOnG-RrSeT.DnSsEc-FaIlEd.ExAmPlE.CoM.", dns.TypeA)
	req.SetEdns0(4096, true)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	assertRRSIGWrongRRsetGadget(t, msg, zsk)
}

// Baseline: all-lowercase qname must hit the same rrsig-wrong-rrset signing branch.
func TestSigner_SignResponse_rrsig_wrong_rrset(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("rrsig-wrong-rrset.dnssec-failed.example.com.", dns.TypeA)
	req.SetEdns0(4096, true)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	assertRRSIGWrongRRsetGadget(t, msg, zsk)
}

// sig-fail gadget must still get a corrupted RRSIG when the qname uses 0x20 case randomization.
func TestSigner_SignResponse_sig_fail_mixedCaseQname_VerifyFails(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("SiG-FaIl.DnSsEc-FaIlEd.ExAmPlE.CoM.", dns.TypeA)
	req.SetEdns0(4096, true)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	a, rrsig := findAAndRRSIG(t, msg)
	if err := rrsig.Verify(zsk.DNSKEY, []dns.RR{a}); err == nil {
		t.Fatal("sig-fail (mixed-case qname): RRSIG.Verify should fail (corrupted signature)")
	}
}

// Ordinary gadget + mixed-case qname: RRSIG must still validate (guards against over-broad lowercasing).
func TestSigner_SignResponse_myip_mixedCaseQname_RRSIGVerifies(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("MyIp.ExAmPlE.CoM.", dns.TypeA)
	req.SetEdns0(4096, true)
	addr, _ := net.ResolveUDPAddr("udp", "192.0.2.9:5353")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	a, rrsig := findAAndRRSIG(t, msg)
	if !a.A.Equal(net.ParseIP("192.0.2.9")) {
		t.Fatalf("unexpected A %s", a.A)
	}
	if err := rrsig.Verify(zsk.DNSKEY, []dns.RR{a}); err != nil {
		t.Fatalf("myip (mixed-case qname): RRSIG.Verify: %v", err)
	}
	if !strings.EqualFold(strings.TrimSuffix(rrsig.Hdr.Name, "."), strings.TrimSuffix(req.Question[0].Name, ".")) {
		t.Errorf("RRSIG owner should echo qname case: rrsig=%q question=%q", rrsig.Hdr.Name, req.Question[0].Name)
	}
}

func TestSigner_SignResponse_nsec3_instead(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	h := handler.New(handler.Config{Domain: "example.com", Signer: signer})
	req := new(dns.Msg)
	req.SetQuestion("nsec3-instead.dnssec-failed.example.com.", dns.TypeA)
	req.SetEdns0(4096, true) // DO bit so signer adds NSEC3
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	var hasNSEC3 bool
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == dns.TypeNSEC3 {
			hasNSEC3 = true
			break
		}
	}
	if !hasNSEC3 {
		t.Error("nsec3-instead: Ns should contain NSEC3 RR(s)")
	}
}

// TestSigner_ExistingNames_ContainsKnownLabels ensures the signer's NSEC name list includes
// key names served by the handler (apex, www, diag, help, gadget labels). Catches drift when
// adding new handler hosts/gadgets without updating the signer's existingNames.
func TestSigner_ExistingNames_ContainsKnownLabels(t *testing.T) {
	ksk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	zsk, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	signer := NewSigner("example.com", ksk, zsk)
	names := signer.ExistingNames()
	nameSet := make(map[string]struct{})
	for _, n := range names {
		nameSet[n] = struct{}{}
	}
	// Apex, special hosts, and representative gadgets (keep in sync with handler + signer list).
	want := []string{
		"example.com.",
		"www.example.com.",
		"diag.example.com.",
		"help.example.com.",
		"myip.example.com.",
		"counter.example.com.",
		"sig-fail.dnssec-failed.example.com.",
	}
	for _, w := range want {
		if _, ok := nameSet[w]; !ok {
			t.Errorf("ExistingNames missing %q (add to signer list when adding handler host/gadget)", w)
		}
	}
}
