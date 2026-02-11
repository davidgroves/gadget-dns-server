package handler

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testHandler creates a Handler with Config{Domain: domain} and applies optional overrides.
// Use for tests that need minimal config; pass overrides to set ServerIPs, Signer, etc.
func testHandler(domain string, overrides ...func(*Config)) *Handler {
	cfg := Config{Domain: domain}
	for _, f := range overrides {
		f(&cfg)
	}
	return New(cfg)
}

func TestHandler_Handle_ApexSOA(t *testing.T) {
	h := testHandler("example.com")
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeSOA)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d want 0", msg.Rcode)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("len(Answer)=%d want 1", len(msg.Answer))
	}
	if soa, ok := msg.Answer[0].(*dns.SOA); !ok {
		t.Fatalf("Answer[0] not SOA")
	} else if soa.Ns != "example.com." {
		t.Errorf("SOA.Ns=%q", soa.Ns)
	}
}

func TestHandler_Handle_MyIP_A(t *testing.T) {
	h := testHandler("example.com")
	req := new(dns.Msg)
	req.SetQuestion("myip.example.com.", dns.TypeA)
	addr, _ := net.ResolveUDPAddr("udp", "192.168.1.1:5353")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("len(Answer)=%d want 1 (A only)", len(msg.Answer))
	}
	if a, ok := msg.Answer[0].(*dns.A); !ok {
		t.Fatalf("Answer[0] not A")
	} else if !a.A.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("A=%s", a.A)
	}
	if len(msg.Extra) != 1 {
		t.Fatalf("len(Extra)=%d want 1 (AAAA in Additional)", len(msg.Extra))
	}
	if aaaa, ok := msg.Extra[0].(*dns.AAAA); !ok {
		t.Fatalf("Extra[0] not AAAA")
	} else if !aaaa.AAAA.Equal(net.IPv6zero) {
		t.Errorf("AAAA placeholder=%s", aaaa.AAAA)
	}
}

func TestHandler_Handle_MyIP_AAAA(t *testing.T) {
	h := testHandler("example.com")
	req := new(dns.Msg)
	req.SetQuestion("myip.example.com.", dns.TypeAAAA)
	addr, _ := net.ResolveUDPAddr("udp", "[::1]:5353")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("len(Answer)=%d want 1 (AAAA only)", len(msg.Answer))
	}
	if aaaa, ok := msg.Answer[0].(*dns.AAAA); !ok {
		t.Fatalf("Answer[0] not AAAA")
	} else if !aaaa.AAAA.Equal(net.IPv6loopback) {
		t.Errorf("AAAA=%s", aaaa.AAAA)
	}
	if len(msg.Extra) != 1 {
		t.Fatalf("len(Extra)=%d want 1 (A in Additional)", len(msg.Extra))
	}
	if a, ok := msg.Extra[0].(*dns.A); !ok {
		t.Fatalf("Extra[0] not A")
	} else if !a.A.Equal(net.IPv4zero) {
		t.Errorf("A placeholder=%s", a.A)
	}
}

func TestHandler_Handle_MyPort(t *testing.T) {
	h := testHandler("example.com")
	req := new(dns.Msg)
	req.SetQuestion("myport.example.com.", dns.TypeTXT)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("len(Answer)=%d", len(msg.Answer))
	}
	if txt, ok := msg.Answer[0].(*dns.TXT); !ok {
		t.Fatalf("not TXT")
	} else if len(txt.Txt) != 1 || txt.Txt[0] != "12345" {
		t.Errorf("Txt=%v", txt.Txt)
	}
}

func TestHandler_Handle_Counter(t *testing.T) {
	h := testHandler("example.com")
	req := new(dns.Msg)
	req.SetQuestion("counter.example.com.", dns.TypeTXT)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	m1 := h.Handle(req, addr, "")
	m2 := h.Handle(req, addr, "")
	if len(m1.Answer) != 1 || len(m2.Answer) != 1 {
		t.Fatalf("answers")
	}
	t1 := m1.Answer[0].(*dns.TXT).Txt[0]
	t2 := m2.Answer[0].(*dns.TXT).Txt[0]
	if t1 == t2 {
		t.Errorf("counter should increment: %s %s", t1, t2)
	}
}

func TestHandler_Handle_RefusedOutsideZone(t *testing.T) {
	h := testHandler("example.com")
	req := new(dns.Msg)
	req.SetQuestion("other.org.", dns.TypeA)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeRefused {
		t.Errorf("rcode=%d want Refused", msg.Rcode)
	}
}

func TestHandler_Handle_NXDOMAIN_UnknownLabel(t *testing.T) {
	h := testHandler("example.com")
	req := new(dns.Msg)
	req.SetQuestion("unknownlabel.example.com.", dns.TypeA)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeNameError {
		t.Errorf("rcode=%d want NXDOMAIN", msg.Rcode)
	}
}

func TestHandler_Handle_SigFailDnssecFailed_A(t *testing.T) {
	h := testHandler("dnssrc.fibrecat.org")
	req := new(dns.Msg)
	req.SetQuestion("sig-fail.dnssec-failed.dnssrc.fibrecat.org.", dns.TypeA)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d want Success", msg.Rcode)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("len(Answer)=%d want 1", len(msg.Answer))
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("Answer[0] not A")
	}
	if !a.A.Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("A=%s want 192.0.2.1", a.A)
	}
	if !strings.HasSuffix(strings.TrimSuffix(a.Hdr.Name, "."), "sig-fail.dnssec-failed.dnssrc.fibrecat.org") {
		t.Errorf("owner=%q", a.Hdr.Name)
	}
}

func TestHandler_Handle_Random_TXT(t *testing.T) {
	h := testHandler("example.com")
	req := new(dns.Msg)
	req.SetQuestion("random.example.com.", dns.TypeTXT)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("len(Answer)=%d", len(msg.Answer))
	}
	txt := msg.Answer[0].(*dns.TXT).Txt[0]
	if len(txt) < 8 {
		t.Errorf("random txt too short: %q", txt)
	}
}

func TestHandler_Handle_TimestampN(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")

	// timestamp-60: TTL 60, value in milliseconds
	req := new(dns.Msg)
	req.SetQuestion("timestamp-60.example.com.", dns.TypeTXT)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("timestamp-60: rcode=%d len=%d", msg.Rcode, len(msg.Answer))
	}
	if msg.Answer[0].Header().Ttl != 60 {
		t.Errorf("timestamp-60 TTL=%d want 60", msg.Answer[0].Header().Ttl)
	}

	// timestamp-0: TTL 0
	req.SetQuestion("timestamp-0.example.com.", dns.TypeTXT)
	msg = h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("timestamp-0: rcode=%d len=%d", msg.Rcode, len(msg.Answer))
	}
	if msg.Answer[0].Header().Ttl != 0 {
		t.Errorf("timestamp-0 TTL=%d want 0", msg.Answer[0].Header().Ttl)
	}
}

func TestHandler_Handle_Protocol(t *testing.T) {
	h := testHandler("example.com")
	req := new(dns.Msg)
	req.SetQuestion("protocol.example.com.", dns.TypeTXT)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "UDP")
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("rcode=%d len=%d", msg.Rcode, len(msg.Answer))
	}
	if txt, ok := msg.Answer[0].(*dns.TXT); !ok || len(txt.Txt) != 1 || txt.Txt[0] != "UDP" {
		t.Errorf("protocol TXT=%v", msg.Answer[0])
	}
}

func TestHandler_Handle_ConnectionURL(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "192.0.2.1:5353")
	for _, label := range []string{"connection", "myconnection"} {
		req := new(dns.Msg)
		req.SetQuestion(label+".example.com.", dns.TypeTXT)
		msg := h.Handle(req, addr, "DoH")
		if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
			t.Fatalf("%s: rcode=%d len=%d", label, msg.Rcode, len(msg.Answer))
		}
		txt, ok := msg.Answer[0].(*dns.TXT)
		if !ok || len(txt.Txt) != 1 {
			t.Fatalf("%s: not TXT or wrong len", label)
		}
		if txt.Txt[0] != "doh://192.0.2.1:5353" {
			t.Errorf("%s: got %q want doh://192.0.2.1:5353", label, txt.Txt[0])
		}
	}
	// IPv6: bracket in URL
	addr6, _ := net.ResolveUDPAddr("udp", "[2001:db8::1]:853")
	req := new(dns.Msg)
	req.SetQuestion("connection.example.com.", dns.TypeTXT)
	msg := h.Handle(req, addr6, "DoT")
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("DoT IPv6: rcode=%d len=%d", msg.Rcode, len(msg.Answer))
	}
	if got := msg.Answer[0].(*dns.TXT).Txt[0]; got != "dot://[2001:db8::1]:853" {
		t.Errorf("DoT IPv6: got %q want dot://[2001:db8::1]:853", got)
	}
}

func TestHandler_Handle_IP_Port_Addr_Aliases(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "10.0.0.5:12345")
	for _, tc := range []struct {
		label string
		want  []string
	}{
		{"ip", []string{"10.0.0.5"}},
		{"port", []string{"12345"}},
		{"addr", []string{"10.0.0.5", "12345"}},
	} {
		req := new(dns.Msg)
		req.SetQuestion(tc.label+".example.com.", dns.TypeTXT)
		msg := h.Handle(req, addr, "")
		if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
			t.Fatalf("%s: rcode=%d len=%d", tc.label, msg.Rcode, len(msg.Answer))
		}
		txt := msg.Answer[0].(*dns.TXT).Txt
		if len(txt) != len(tc.want) {
			t.Errorf("%s: got %v want %v", tc.label, txt, tc.want)
		} else {
			for i := range txt {
				if txt[i] != tc.want[i] {
					t.Errorf("%s: got %v want %v", tc.label, txt, tc.want)
					break
				}
			}
		}
	}
}

func TestHandler_Handle_TTLN(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	for _, tc := range []struct {
		label string
		want  uint32
		ok    bool
	}{
		{"ttl-0", 0, true},
		{"ttl-60", 60, true},
		{"ttl-300", 300, true},
		{"ttl-86400", 86400, true},
		{"ttl-99999", 0, false},
		{"ttl-x", 0, false},
		{"ttl-", 0, false},
	} {
		req := new(dns.Msg)
		req.SetQuestion(tc.label+".example.com.", dns.TypeTXT)
		msg := h.Handle(req, addr, "")
		if !tc.ok {
			if msg.Rcode != dns.RcodeNameError {
				t.Errorf("label %q: want NXDOMAIN got rcode=%d", tc.label, msg.Rcode)
			}
			continue
		}
		if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
			t.Fatalf("label %q: rcode=%d len=%d", tc.label, msg.Rcode, len(msg.Answer))
		}
		if msg.Answer[0].Header().Ttl != tc.want {
			t.Errorf("label %q: TTL=%d want %d", tc.label, msg.Answer[0].Header().Ttl, tc.want)
		}
	}
}

func TestHandler_Handle_EdnsPadN(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")

	// TXT: response has EDNS padding to >= 256 bytes
	req := new(dns.Msg)
	req.SetQuestion("ednspad-256.example.com.", dns.TypeTXT)
	req.SetEdns0(4096, false)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("TXT: rcode=%d len(Answer)=%d", msg.Rcode, len(msg.Answer))
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) < 256 {
		t.Errorf("ednspad-256 TXT response wire size=%d want >= 256", len(packed))
	}

	// A: response has A record and EDNS padding
	req.SetQuestion("ednspad-256.example.com.", dns.TypeA)
	msgA := h.Handle(req, addr, "")
	if msgA.Rcode != dns.RcodeSuccess || len(msgA.Answer) != 1 {
		t.Fatalf("A: rcode=%d len(Answer)=%d", msgA.Rcode, len(msgA.Answer))
	}
	if _, ok := msgA.Answer[0].(*dns.A); !ok {
		t.Fatalf("A: Answer[0] not *dns.A")
	}
	packedA, _ := msgA.Pack()
	if len(packedA) < 256 {
		t.Errorf("ednspad-256 A response wire size=%d want >= 256", len(packedA))
	}

	// AAAA: response has AAAA record and EDNS padding
	req.SetQuestion("ednspad-256.example.com.", dns.TypeAAAA)
	msgAAAA := h.Handle(req, addr, "")
	if msgAAAA.Rcode != dns.RcodeSuccess || len(msgAAAA.Answer) != 1 {
		t.Fatalf("AAAA: rcode=%d len(Answer)=%d", msgAAAA.Rcode, len(msgAAAA.Answer))
	}
	if _, ok := msgAAAA.Answer[0].(*dns.AAAA); !ok {
		t.Fatalf("AAAA: Answer[0] not *dns.AAAA")
	}
	packedAAAA, _ := msgAAAA.Pack()
	if len(packedAAAA) < 256 {
		t.Errorf("ednspad-256 AAAA response wire size=%d want >= 256", len(packedAAAA))
	}

	// Invalid ednspad-N (below min) should be NXDOMAIN
	req.SetQuestion("ednspad-99.example.com.", dns.TypeTXT)
	msg2 := h.Handle(req, addr, "")
	if msg2.Rcode != dns.RcodeNameError {
		t.Errorf("ednspad-99 (below min): rcode=%d want NXDOMAIN", msg2.Rcode)
	}
}

func TestHandler_Handle_SizeN(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("size-256.example.com.", dns.TypeTXT)
	req.SetEdns0(4096, false)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("rcode=%d len(Answer)=%d", msg.Rcode, len(msg.Answer))
	}
	txt, ok := msg.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("Answer[0] not *dns.TXT")
	}
	if len(txt.Txt) < 1 || txt.Txt[0] != "size-256" {
		t.Errorf("TXT first string=%q want size-256; Txt=%v", txt.Txt[0], txt.Txt)
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) < 256 {
		t.Errorf("size-256 response wire size=%d want >= 256", len(packed))
	}
	// size-N is TXT only: A query gets NODATA
	req.SetQuestion("size-256.example.com.", dns.TypeA)
	msgA := h.Handle(req, addr, "")
	if msgA.Rcode != dns.RcodeSuccess || len(msgA.Answer) != 0 || len(msgA.Ns) != 1 {
		t.Errorf("size-N A: rcode=%d len(Answer)=%d len(Ns)=%d want NODATA", msgA.Rcode, len(msgA.Answer), len(msgA.Ns))
	}
	// Invalid size-N (below min) is NXDOMAIN
	req.SetQuestion("size-99.example.com.", dns.TypeTXT)
	msg2 := h.Handle(req, addr, "")
	if msg2.Rcode != dns.RcodeNameError {
		t.Errorf("size-99: rcode=%d want NXDOMAIN", msg2.Rcode)
	}
}

func TestHandler_Handle_DelayN(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")

	// delay-0: respond immediately
	req := new(dns.Msg)
	req.SetQuestion("delay-0.example.com.", dns.TypeTXT)
	start := time.Now()
	msg := h.Handle(req, addr, "")
	elapsed := time.Since(start)
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("delay-0: rcode=%d len=%d", msg.Rcode, len(msg.Answer))
	}
	if txt, ok := msg.Answer[0].(*dns.TXT); !ok || len(txt.Txt) != 1 || !strings.Contains(txt.Txt[0], "delayed") {
		t.Errorf("delay-0: TXT=%v", msg.Answer[0])
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("delay-0 took %v, expected near-instant", elapsed)
	}

	// delay-10: response after ~10ms
	req.SetQuestion("delay-10.example.com.", dns.TypeTXT)
	start = time.Now()
	msg = h.Handle(req, addr, "")
	elapsed = time.Since(start)
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("delay-10: rcode=%d len=%d", msg.Rcode, len(msg.Answer))
	}
	if elapsed < 8*time.Millisecond || elapsed > 100*time.Millisecond {
		t.Errorf("delay-10 took %v, expected ~10ms", elapsed)
	}
}

func TestHandler_Handle_DelayXY(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("delay-10-50.example.com.", dns.TypeTXT)
	start := time.Now()
	msg := h.Handle(req, addr, "")
	elapsed := time.Since(start)
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("delay-10-50: rcode=%d len=%d", msg.Rcode, len(msg.Answer))
	}
	if txt, ok := msg.Answer[0].(*dns.TXT); !ok || len(txt.Txt) != 1 || !strings.Contains(txt.Txt[0], "delayed") {
		t.Errorf("delay-10-50: TXT=%v", msg.Answer[0])
	}
	if elapsed < 8*time.Millisecond || elapsed > 150*time.Millisecond {
		t.Errorf("delay-10-50 took %v, expected 10–50ms", elapsed)
	}
}

func TestHandler_Handle_DelayN_Invalid(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	for _, label := range []string{"delay", "delay-", "delay-x", "delay-1-0", "delay-999999"} {
		req := new(dns.Msg)
		req.SetQuestion(label+".example.com.", dns.TypeTXT)
		msg := h.Handle(req, addr, "")
		if msg.Rcode != dns.RcodeNameError {
			t.Errorf("label %q: rcode=%d want NXDOMAIN", label, msg.Rcode)
		}
	}
}

func TestHandler_Handle_QnameMin(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	for _, qname := range []string{"qname-min.example.com.", "a.b.c.d.zzzzzzz.qname-min.example.com."} {
		req := new(dns.Msg)
		req.SetQuestion(qname, dns.TypeTXT)
		msg := h.Handle(req, addr, "")
		if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
			t.Fatalf("qname %q: rcode=%d len=%d", qname, msg.Rcode, len(msg.Answer))
		}
		txt := msg.Answer[0].(*dns.TXT).Txt[0]
		if !strings.Contains(txt, "qname received:") || !strings.Contains(txt, "qname-min.example.com") {
			t.Errorf("qname %q: TXT=%q", qname, txt)
		}
	}
}

func TestHandler_Handle_QnameMin_WithRecorder_Sequence(t *testing.T) {
	store := NewQnameMinStore(60*time.Second, 50)
	h := testHandler("example.com", func(c *Config) { c.QnameMinRecorder = store })
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	// First query: qname-min.example.com (simulates resolver's first minimization step)
	req1 := new(dns.Msg)
	req1.SetQuestion("qname-min.example.com.", dns.TypeTXT)
	msg1 := h.Handle(req1, addr, "")
	if msg1.Rcode != dns.RcodeSuccess || len(msg1.Answer) != 1 {
		t.Fatalf("first query: rcode=%d len=%d", msg1.Rcode, len(msg1.Answer))
	}

	// Second query: zzzzzzz.qname-min.example.com (simulates resolver's next minimization step; zzzzzzz is canonical 5th label)
	req2 := new(dns.Msg)
	req2.SetQuestion("zzzzzzz.qname-min.example.com.", dns.TypeTXT)
	msg2 := h.Handle(req2, addr, "")
	if msg2.Rcode != dns.RcodeSuccess || len(msg2.Answer) != 1 {
		t.Fatalf("second query: rcode=%d len=%d", msg2.Rcode, len(msg2.Answer))
	}
	txtRR := msg2.Answer[0].(*dns.TXT)
	if len(txtRR.Txt) < 2 {
		t.Fatalf("expected at least 2 TXT strings (qname received + sequence), got %d", len(txtRR.Txt))
	}
	if !strings.Contains(txtRR.Txt[0], "qname received:") || !strings.Contains(txtRR.Txt[0], "zzzzzzz.qname-min.example.com") {
		t.Errorf("Txt[0]=%q missing qname received", txtRR.Txt[0])
	}
	seqLine := txtRR.Txt[1]
	if !strings.Contains(seqLine, "minimization sequence") {
		t.Errorf("Txt[1]=%q missing minimization sequence", seqLine)
	}
	if !strings.Contains(seqLine, "qname-min.example.com") || !strings.Contains(seqLine, "zzzzzzz.qname-min.example.com") {
		t.Errorf("Txt[1]=%q should contain both qnames in sequence", seqLine)
	}
}

func TestHandler_SetCookie(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-cookie-78797a.example.com.", dns.TypeTXT)
	req.SetEdns0(4096, false)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d want Success", msg.Rcode)
	}
	if len(msg.Answer) != 0 || len(msg.Ns) != 1 {
		t.Fatalf("expected NODATA (0 answer, 1 Ns), got %d answer %d Ns", len(msg.Answer), len(msg.Ns))
	}
	h.FinalizeResponse(req, msg)
	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatal("expected OPT after FinalizeResponse")
	}
	var found bool
	for _, o := range opt.Option {
		if c, ok := o.(*dns.EDNS0_COOKIE); ok {
			if c.Cookie != "78797a" {
				t.Errorf("cookie=%q want 78797a", c.Cookie)
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("OPT has no COOKIE option")
	}
}

func TestHandler_SetCookie_InvalidHex(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-cookie-xyz.example.com.", dns.TypeTXT)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeNameError {
		t.Errorf("set-cookie-xyz (invalid hex): rcode=%d want NXDOMAIN", msg.Rcode)
	}
}

func TestHandler_SetCookie_NoEDNS(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-cookie-616263.example.com.", dns.TypeTXT)
	// no SetEdns0
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatal("expected OPT created for set-cookie when request had no EDNS")
	}
	var found bool
	for _, o := range opt.Option {
		if c, ok := o.(*dns.EDNS0_COOKIE); ok && c.Cookie == "616263" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("OPT has no COOKIE option with value 616263")
	}
}

func TestHandler_EDNS_BadVers(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("myip.example.com.", dns.TypeA)
	req.SetEdns0(4096, false)
	req.IsEdns0().SetVersion(1)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeBadVers {
		t.Errorf("EDNS version 1: rcode=%d want BADVERS (%d)", msg.Rcode, dns.RcodeBadVers)
	}
	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatal("BADVERS response must include OPT indicating supported version (0)")
	}
	if opt.Version() != 0 {
		t.Errorf("OPT version=%d want 0", opt.Version())
	}
	h.FinalizeResponse(req, msg)
	if msg.Rcode != dns.RcodeBadVers {
		t.Errorf("after FinalizeResponse: rcode=%d want BADVERS", msg.Rcode)
	}
	if msg.IsEdns0() == nil || msg.IsEdns0().Version() != 0 {
		t.Error("FinalizeResponse must not overwrite BADVERS OPT")
	}
}

func TestHandler_NSID_Default(t *testing.T) {
	h := testHandler("example.com", func(c *Config) { c.Hostname = "ns1.example.com" })
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeSOA)
	req.SetEdns0(4096, false)
	req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_NSID{Nsid: ""})
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatal("expected OPT in response")
	}
	var nsidOpt *dns.EDNS0_NSID
	for _, o := range opt.Option {
		if n, ok := o.(*dns.EDNS0_NSID); ok {
			nsidOpt = n
			break
		}
	}
	if nsidOpt == nil {
		t.Fatal("expected NSID option in response when client sent NSID")
	}
	decoded, err := hex.DecodeString(nsidOpt.Nsid)
	if err != nil {
		t.Fatalf("NSID not valid hex: %v", err)
	}
	if string(decoded) != "ns1.example.com" {
		t.Errorf("NSID=%q (decoded from %q) want ns1.example.com", string(decoded), nsidOpt.Nsid)
	}
}

func TestHandler_NSID_SetNSID(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-nsid-my-server-1.example.com.", dns.TypeTXT)
	req.SetEdns0(4096, false)
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatal("expected OPT in response")
	}
	var nsidOpt *dns.EDNS0_NSID
	for _, o := range opt.Option {
		if n, ok := o.(*dns.EDNS0_NSID); ok {
			nsidOpt = n
			break
		}
	}
	if nsidOpt == nil {
		t.Fatal("expected NSID option from set-nsid gadget")
	}
	decoded, err := hex.DecodeString(nsidOpt.Nsid)
	if err != nil {
		t.Fatalf("NSID not valid hex: %v", err)
	}
	if string(decoded) != "my-server-1" {
		t.Errorf("NSID=%q (decoded from %q) want my-server-1", string(decoded), nsidOpt.Nsid)
	}
}

func TestHandler_NSID_SetNSID_OverridesDefault(t *testing.T) {
	h := testHandler("example.com", func(c *Config) { c.Hostname = "ns1.example.com" })
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-nsid-custom.example.com.", dns.TypeTXT)
	req.SetEdns0(4096, false)
	req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_NSID{Nsid: ""})
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatal("expected OPT in response")
	}
	var nsidOpt *dns.EDNS0_NSID
	for _, o := range opt.Option {
		if n, ok := o.(*dns.EDNS0_NSID); ok {
			nsidOpt = n
			break
		}
	}
	if nsidOpt == nil {
		t.Fatal("expected NSID option")
	}
	decoded, _ := hex.DecodeString(nsidOpt.Nsid)
	if string(decoded) != "custom" {
		t.Errorf("set-nsid should override default: NSID=%q want custom", string(decoded))
	}
}

func TestHandler_SetNoEDNS(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-noedns.example.com.", dns.TypeTXT)
	req.SetEdns0(4096, false)
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	if msg.IsEdns0() != nil {
		t.Error("set-noedns: response must not include OPT record")
	}
}

func TestHandler_SetNoEDNS_WithGadget(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-noedns.myip.example.com.", dns.TypeA)
	req.SetEdns0(4096, false)
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	if msg.IsEdns0() != nil {
		t.Error("set-noedns.myip: response must not include OPT record")
	}
}

func TestHandler_SetNoEDNS_TruncateTo512(t *testing.T) {
	// set-noedns with a response that would exceed 512 bytes: must set TC and truncate to 512 (RFC 1034/1035)
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-noedns.size-600.example.com.", dns.TypeTXT)
	req.SetEdns0(4096, false)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("Handle: rcode=%d len(Answer)=%d", msg.Rcode, len(msg.Answer))
	}
	h.FinalizeResponse(req, msg)
	if msg.IsEdns0() != nil {
		t.Error("set-noedns: response must not include OPT after FinalizeResponse")
	}
	if !msg.Truncated {
		t.Error("set-noedns with large response: Truncated must be true")
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) > 512 {
		t.Errorf("set-noedns response size=%d must be <= 512 (RFC 1034/1035)", len(packed))
	}
}

func TestHandler_SetNoEDNS_TakesPriorityOverEDNSOptions(t *testing.T) {
	// set-noedns must take priority: combined with set-cookie, set-ede, set-nsid, or client NSID, response has no OPT
	h := testHandler("example.com", func(c *Config) { c.Hostname = "ns1.example.com" })
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	tests := []string{
		"set-noedns.set-cookie-616263.example.com.",
		"set-cookie-616263.set-noedns.example.com.",
		"set-noedns.set-ede-5-foo.example.com.",
		"set-noedns.set-nsid-custom.example.com.",
	}
	for _, qname := range tests {
		req := new(dns.Msg)
		req.SetQuestion(qname, dns.TypeTXT)
		req.SetEdns0(4096, false)
		req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_NSID{Nsid: ""})
		msg := h.Handle(req, addr, "")
		h.FinalizeResponse(req, msg)
		if msg.IsEdns0() != nil {
			t.Errorf("set-noedns must take priority: %q response must not include OPT", qname)
		}
	}
}

func TestHandler_CH_HostnameBind(t *testing.T) {
	h := testHandler("example.com", func(c *Config) { c.Hostname = "ns1.example.com" })
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.Question = []dns.Question{{Name: "hostname.bind.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}}
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d want Success", msg.Rcode)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("len(Answer)=%d want 1", len(msg.Answer))
	}
	txt, ok := msg.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("Answer[0] not TXT")
	}
	if txt.Hdr.Class != dns.ClassCHAOS {
		t.Errorf("TXT Class=%d want CH (3)", txt.Hdr.Class)
	}
	if len(txt.Txt) != 1 || txt.Txt[0] != "ns1.example.com" {
		t.Errorf("TXT Txt=%v want [ns1.example.com]", txt.Txt)
	}
	// Default hostname is domain when not set
	h2 := testHandler("example.com")
	req2 := new(dns.Msg)
	req2.Question = []dns.Question{{Name: "hostname.bind.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}}
	msg2 := h2.Handle(req2, addr, "")
	if len(msg2.Answer) != 1 {
		t.Fatalf("default hostname: len(Answer)=%d want 1", len(msg2.Answer))
	}
	if msg2.Answer[0].(*dns.TXT).Txt[0] != "example.com" {
		t.Errorf("default hostname TXT=%v want [example.com]", msg2.Answer[0].(*dns.TXT).Txt)
	}
}

func TestHandler_CH_VersionBind(t *testing.T) {
	h := testHandler("example.com", func(c *Config) { c.Version = "1.2.3" })
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.Question = []dns.Question{{Name: "version.bind.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}}
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d want Success", msg.Rcode)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("len(Answer)=%d want 1", len(msg.Answer))
	}
	txt, ok := msg.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("Answer[0] not TXT")
	}
	if txt.Hdr.Class != dns.ClassCHAOS {
		t.Errorf("TXT Class=%d want CH (3)", txt.Hdr.Class)
	}
	want := []string{"gadget-dns-server 1.2.3", GitHubProjectURL}
	if len(txt.Txt) != len(want) || txt.Txt[0] != want[0] || txt.Txt[1] != want[1] {
		t.Errorf("TXT Txt=%v want %v", txt.Txt, want)
	}
	// Empty version shows "unknown"
	h2 := testHandler("example.com")
	req2 := new(dns.Msg)
	req2.Question = []dns.Question{{Name: "version.bind.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}}
	msg2 := h2.Handle(req2, addr, "")
	if msg2.Answer[0].(*dns.TXT).Txt[0] != "gadget-dns-server unknown" {
		t.Errorf("empty version TXT[0]=%q want gadget-dns-server unknown", msg2.Answer[0].(*dns.TXT).Txt[0])
	}
}

func TestHandler_CH_OtherBind_NODATA(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.Question = []dns.Question{{Name: "authors.bind.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}}
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d want Success", msg.Rcode)
	}
	if len(msg.Answer) != 0 {
		t.Errorf("len(Answer)=%d want 0 (NODATA)", len(msg.Answer))
	}
}

func TestHandler_SetEDE(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-ede-5-foo.example.com.", dns.TypeTXT)
	req.SetEdns0(4096, false)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d want Success", msg.Rcode)
	}
	h.FinalizeResponse(req, msg)
	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatal("expected OPT after FinalizeResponse")
	}
	var found bool
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_EDE); ok {
			if e.InfoCode != 5 || e.ExtraText != "foo" {
				t.Errorf("EDE InfoCode=%d ExtraText=%q want 5 foo", e.InfoCode, e.ExtraText)
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("OPT has no EDE option")
	}
}

func TestHandler_SetEDE_NoText(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-ede-12.example.com.", dns.TypeA)
	req.SetEdns0(4096, false)
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatal("expected OPT")
	}
	var found bool
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_EDE); ok && e.InfoCode == 12 && e.ExtraText == "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("OPT has no EDE option with code 12 and empty text")
	}
}

func TestHandler_SetEDE_Invalid(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-ede-xyz.example.com.", dns.TypeTXT)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeNameError {
		t.Errorf("invalid set-ede-xyz: rcode=%d want NXDOMAIN", msg.Rcode)
	}
}

func TestHandler_SetFlags(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-flags-0x8180.example.com.", dns.TypeTXT)
	req.SetEdns0(4096, false)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d want Success", msg.Rcode)
	}
	h.FinalizeResponse(req, msg)
	// 0x8180 = 33152 = bits 15 (QR), 8 (RD), 7 (RA) set
	if !msg.Response {
		t.Error("flags 0x8180: Response want true")
	}
	if !msg.RecursionDesired {
		t.Error("flags 0x8180: RecursionDesired want true")
	}
	if !msg.RecursionAvailable {
		t.Error("flags 0x8180: RecursionAvailable want true")
	}
	if msg.Opcode != 0 || msg.Truncated || msg.Authoritative {
		t.Errorf("flags 0x8180: Opcode=%d TC=%v AA=%v want 0 false false", msg.Opcode, msg.Truncated, msg.Authoritative)
	}
}

func TestHandler_SetFlags_Decimal(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-flags-23.example.com.", dns.TypeTXT)
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	// 23 = 0x17 = binary 10111 -> Rcode 7 (NXDOMAIN), RD=1, RA=1, etc.
	if msg.Rcode != 7 {
		t.Errorf("set-flags-23: Rcode=%d want 7", msg.Rcode)
	}
}

func TestHandler_SetFlags_Invalid(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-flags-0x12345.example.com.", dns.TypeTXT)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeNameError {
		t.Errorf("set-flags-0x12345 (over 16 bits): rcode=%d want NXDOMAIN", msg.Rcode)
	}
}

func TestHandler_SetRcode(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-rcode-3.example.com.", dns.TypeTXT)
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	if msg.Rcode != dns.RcodeNameError {
		t.Errorf("set-rcode-3: Rcode=%d want 3 (NXDOMAIN)", msg.Rcode)
	}
}

func TestHandler_SetStatus_Name(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-status-NXDOMAIN.example.com.", dns.TypeTXT)
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	if msg.Rcode != dns.RcodeNameError {
		t.Errorf("set-status-NXDOMAIN: Rcode=%d want NXDOMAIN (3)", msg.Rcode)
	}
}

func TestHandler_SetID(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-id-0x1234.example.com.", dns.TypeTXT)
	msg := h.Handle(req, addr, "")
	origID := msg.Id
	h.FinalizeResponse(req, msg)
	if msg.Id != 0x1234 {
		t.Errorf("set-id-0x1234: Id=%d want 0x1234", msg.Id)
	}
	// Without set-id, response would have echoed request Id (or random); after set-id it is 0x1234
	_ = origID
}

func TestHandler_SetRcode_Invalid(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-rcode-badvalue.example.com.", dns.TypeTXT)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeNameError {
		t.Errorf("set-rcode-badvalue: rcode=%d want NXDOMAIN", msg.Rcode)
	}
}

func TestHandler_SetID_Invalid(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-id-99999.example.com.", dns.TypeTXT)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeNameError {
		t.Errorf("set-id-99999 (over 16 bits): rcode=%d want NXDOMAIN", msg.Rcode)
	}
}

func TestHandler_StackedSetOptions_SetCookieAndSetTTL(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-cookie-616263.set-ttl-20.example.com.", dns.TypeTXT)
	req.SetEdns0(4096, false)
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	// NODATA (set-options only); FinalizeResponse applies both cookie and set-ttl.
	if msg.Rcode != dns.RcodeSuccess {
		t.Errorf("set-cookie-616263.set-ttl-20: rcode=%d want Success (NODATA)", msg.Rcode)
	}
	if len(msg.Ns) < 1 {
		t.Fatal("expected at least one Ns (SOA)")
	}
	if msg.Ns[0].Header().Ttl != 20 {
		t.Errorf("set-ttl-20: Ns[0].Ttl=%d want 20", msg.Ns[0].Header().Ttl)
	}
	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatal("expected OPT after FinalizeResponse")
	}
	var found bool
	for _, o := range opt.Option {
		if c, ok := o.(*dns.EDNS0_COOKIE); ok && c.Cookie == "616263" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("OPT has no COOKIE option with value 616263")
	}
}

func TestHandler_SetTTL_Alone(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-ttl-60.example.com.", dns.TypeTXT)
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	if len(msg.Ns) < 1 {
		t.Fatal("expected at least one Ns (SOA)")
	}
	if msg.Ns[0].Header().Ttl != 60 {
		t.Errorf("set-ttl-60: Ns[0].Ttl=%d want 60", msg.Ns[0].Header().Ttl)
	}
}

func TestHandler_SetDelay(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	// set-delay-0.counter: counter response with no delay
	req := new(dns.Msg)
	req.SetQuestion("set-delay-0.counter.example.com.", dns.TypeTXT)
	start := time.Now()
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	elapsed := time.Since(start)
	if msg.Rcode != dns.RcodeSuccess {
		t.Errorf("set-delay-0.counter: rcode=%d want Success", msg.Rcode)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("set-delay-0.counter: len(Answer)=%d want 1", len(msg.Answer))
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("set-delay-0 took %v, expected near-instant", elapsed)
	}
	// set-delay-only (set-options only): NODATA after delay
	req.SetQuestion("set-delay-0.example.com.", dns.TypeTXT)
	msg = h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	if msg.Rcode != dns.RcodeSuccess || len(msg.Ns) < 1 {
		t.Errorf("set-delay-0 only: rcode=%d len(Ns)=%d", msg.Rcode, len(msg.Ns))
	}
}

func TestHandler_SetAnswer_A(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-answer-1-2-3-4.set-answer-5-6-7-8.example.com.", dns.TypeA)
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	if msg.Rcode != dns.RcodeSuccess {
		t.Errorf("set-answer A: rcode=%d want Success", msg.Rcode)
	}
	if len(msg.Answer) != 2 {
		t.Fatalf("set-answer A: len(Answer)=%d want 2", len(msg.Answer))
	}
	for i, want := range []string{"1.2.3.4", "5.6.7.8"} {
		if a, ok := msg.Answer[i].(*dns.A); !ok {
			t.Errorf("Answer[%d] not A record", i)
		} else if a.A.String() != want {
			t.Errorf("Answer[%d].A=%s want %s", i, a.A.String(), want)
		}
	}
}

func TestHandler_SetAnswer_TXT(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-answer-txt-hello.set-answer-txt-world.example.com.", dns.TypeTXT)
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	if msg.Rcode != dns.RcodeSuccess {
		t.Errorf("set-answer-txt TXT: rcode=%d want Success", msg.Rcode)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("set-answer-txt TXT: len(Answer)=%d want 1", len(msg.Answer))
	}
	txt, ok := msg.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatal("Answer[0] not TXT record")
	}
	if len(txt.Txt) != 2 {
		t.Fatalf("TXT Txt len=%d want 2", len(txt.Txt))
	}
	if txt.Txt[0] != "hello" || txt.Txt[1] != "world" {
		t.Errorf("TXT Txt=%v want [hello world]", txt.Txt)
	}
}

func TestHandler_SetAnswer_Diag(t *testing.T) {
	// x.set-answer-1-2-3-4.set-answer-5-6-7-8.foo.diag.example.com A -> 1.2.3.4 and 5.6.7.8
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("x.set-answer-1-2-3-4.set-answer-5-6-7-8.foo.diag.example.com.", dns.TypeA)
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	if msg.Rcode != dns.RcodeSuccess {
		t.Errorf("set-answer diag A: rcode=%d want Success", msg.Rcode)
	}
	if len(msg.Answer) != 2 {
		t.Fatalf("set-answer diag A: len(Answer)=%d want 2", len(msg.Answer))
	}
	for i, want := range []string{"1.2.3.4", "5.6.7.8"} {
		if a, ok := msg.Answer[i].(*dns.A); !ok {
			t.Errorf("Answer[%d] not A record", i)
		} else if a.A.String() != want {
			t.Errorf("Answer[%d].A=%s want %s", i, a.A.String(), want)
		}
	}
}

func TestHandler_DiagTokenOnly_ChainedSetOptions(t *testing.T) {
	// Mirrors: dig set-cookie-78797a.set-ede-5-foo.mytoken.diag.example.com TXT
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("set-cookie-78797a.set-ede-5-foo.mytoken.diag.example.com.", dns.TypeTXT)
	req.SetEdns0(4096, false)
	msg := h.Handle(req, addr, "")
	h.FinalizeResponse(req, msg)
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d want Success", msg.Rcode)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("got %d answer RRs want 1", len(msg.Answer))
	}
	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatal("expected OPT after FinalizeResponse")
	}
	var hasCookie, hasEDE bool
	for _, o := range opt.Option {
		if c, ok := o.(*dns.EDNS0_COOKIE); ok && c.Cookie == "78797a" {
			hasCookie = true
		}
		if e, ok := o.(*dns.EDNS0_EDE); ok && e.InfoCode == 5 && e.ExtraText == "foo" {
			hasEDE = true
		}
	}
	if !hasCookie {
		t.Error("OPT missing COOKIE option with value 78797a")
	}
	if !hasEDE {
		t.Error("OPT missing EDE option code=5 extra=foo")
	}
	// Ensure response can be packed (WriteMsg uses Pack; failure would cause no response)
	if _, err := msg.Pack(); err != nil {
		t.Fatalf("msg.Pack() failed: %v", err)
	}
}

func TestHandler_DiagWithGadget_Connection(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("connection.foo.diag.example.com.", dns.TypeTXT)
	msg := h.Handle(req, addr, "dot")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("connection.foo.diag: rcode=%d want Success", msg.Rcode)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("connection.foo.diag: got %d answer RRs want 1", len(msg.Answer))
	}
	txt, ok := msg.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("connection.foo.diag: answer is %T want *dns.TXT", msg.Answer[0])
	}
	if len(txt.Txt) == 0 || !strings.Contains(txt.Txt[0], "dot://") {
		t.Errorf("connection.foo.diag: TXT=%v want connection URL (dot://...)", txt.Txt)
	}
	// Token-only diag still returns "View queries at ..."; gadget-under-diag returns gadget response only
	if strings.Contains(txt.Txt[0], "View queries at") {
		t.Error("connection.foo.diag: expected gadget response (connection URL), not diag view URL")
	}
}

func TestHandler_Help_TXT(t *testing.T) {
	h := testHandler("dnssrc.fibrecat.org")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("help.dnssrc.fibrecat.org.", dns.TypeTXT)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("help TXT: rcode=%d want Success", msg.Rcode)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("help TXT: len(Answer)=%d want 1", len(msg.Answer))
	}
	txt, ok := msg.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("help TXT: answer is %T want *dns.TXT", msg.Answer[0])
	}
	want := "https://www.dnssrc.fibrecat.org"
	if len(txt.Txt) != 1 || txt.Txt[0] != want {
		t.Errorf("help TXT: Txt=%v want [%s]", txt.Txt, want)
	}
}

func TestHandler_TxtTest(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	tests := []struct {
		qname string
		want  string
	}{
		{"alert.txt-test.example.com.", `<script>alert(1)</script>`},
		{"href.txt-test.example.com.", "https://example.com/"},
		{"bobby-tables.txt-test.example.com.", `' OR '1'='1`},
	}
	for _, tt := range tests {
		req := new(dns.Msg)
		req.SetQuestion(tt.qname, dns.TypeTXT)
		msg := h.Handle(req, addr, "")
		if msg.Rcode != dns.RcodeSuccess {
			t.Errorf("%s: rcode=%d want Success", tt.qname, msg.Rcode)
			continue
		}
		if len(msg.Answer) != 1 {
			t.Errorf("%s: len(Answer)=%d want 1", tt.qname, len(msg.Answer))
			continue
		}
		txt, ok := msg.Answer[0].(*dns.TXT)
		if !ok {
			t.Errorf("%s: Answer[0] is %T want *dns.TXT", tt.qname, msg.Answer[0])
			continue
		}
		if len(txt.Txt) != 1 || txt.Txt[0] != tt.want {
			t.Errorf("%s: Txt=%v want [%q]", tt.qname, txt.Txt, tt.want)
		}
	}
}

func TestHandler_NsTestUnresolvable(t *testing.T) {
	h := testHandler("example.com")
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("unresolvable.ns-test.example.com.", dns.TypeA)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("unresolvable.ns-test: rcode=%d want Success", msg.Rcode)
	}
	if len(msg.Answer) != 0 {
		t.Fatalf("unresolvable.ns-test: len(Answer)=%d want 0 (referral)", len(msg.Answer))
	}
	if len(msg.Ns) != 2 {
		t.Fatalf("unresolvable.ns-test: len(Ns)=%d want 2", len(msg.Ns))
	}
	for i, rr := range msg.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			t.Errorf("Ns[%d] is %T want *dns.NS", i, rr)
			continue
		}
		if ns.Hdr.Rrtype != dns.TypeNS {
			t.Errorf("Ns[%d] Rrtype=%d want NS", i, ns.Hdr.Rrtype)
		}
	}
	// ns1 and ns2 should be present
	names := []string{msg.Ns[0].(*dns.NS).Ns, msg.Ns[1].(*dns.NS).Ns}
	if !((strings.HasSuffix(names[0], "ns1.unresolvable.ns-test.example.com.") && strings.HasSuffix(names[1], "ns2.unresolvable.ns-test.example.com.")) ||
		(strings.HasSuffix(names[0], "ns2.unresolvable.ns-test.example.com.") && strings.HasSuffix(names[1], "ns1.unresolvable.ns-test.example.com."))) {
		t.Errorf("unresolvable.ns-test: Ns targets=%v want ns1/ns2.unresolvable.ns-test.example.com.", names)
	}
}

func TestFirstLabelUnderZone(t *testing.T) {
	tests := []struct {
		qname, domain, want string
	}{
		{"myip.example.com", "example.com", "myip"},
		{"set-cookie-xyz.example.com", "example.com", "set-cookie-xyz"},
		{"a.b.example.com", "example.com", "b"},
		{"example.com", "example.com", ""},
		{"other.com", "example.com", ""},
		{"notunder.example.org", "example.com", ""},
	}
	for _, tt := range tests {
		got := firstLabelUnderZone(tt.qname, tt.domain)
		if got != tt.want {
			t.Errorf("firstLabelUnderZone(%q, %q)=%q want %q", tt.qname, tt.domain, got, tt.want)
		}
	}
}
