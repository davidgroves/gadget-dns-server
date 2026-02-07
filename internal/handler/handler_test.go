package handler

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestHandler_Handle_ApexSOA(t *testing.T) {
	h := New(Config{Domain: "example.com"})
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
	h := New(Config{Domain: "example.com"})
	req := new(dns.Msg)
	req.SetQuestion("myip.example.com.", dns.TypeA)
	addr, _ := net.ResolveUDPAddr("udp", "192.168.1.1:5353")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d", msg.Rcode)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("len(Answer)=%d want 1", len(msg.Answer))
	}
	if a, ok := msg.Answer[0].(*dns.A); !ok {
		t.Fatalf("not A record")
	} else if !a.A.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("A=%s", a.A)
	}
}

func TestHandler_Handle_MyPort(t *testing.T) {
	h := New(Config{Domain: "example.com"})
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
	h := New(Config{Domain: "example.com"})
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
	h := New(Config{Domain: "example.com"})
	req := new(dns.Msg)
	req.SetQuestion("other.org.", dns.TypeA)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeRefused {
		t.Errorf("rcode=%d want Refused", msg.Rcode)
	}
}

func TestHandler_Handle_NXDOMAIN_UnknownLabel(t *testing.T) {
	h := New(Config{Domain: "example.com"})
	req := new(dns.Msg)
	req.SetQuestion("unknownlabel.example.com.", dns.TypeA)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeNameError {
		t.Errorf("rcode=%d want NXDOMAIN", msg.Rcode)
	}
}

func TestHandler_Handle_Random_TXT(t *testing.T) {
	h := New(Config{Domain: "example.com"})
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

func TestHandler_Handle_Timestamp(t *testing.T) {
	h := New(Config{Domain: "example.com"})
	req := new(dns.Msg)
	req.SetQuestion("timestamp.example.com.", dns.TypeTXT)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("rcode=%d len=%d", msg.Rcode, len(msg.Answer))
	}
	// TTL 60 for timestamp
	if msg.Answer[0].Header().Ttl != 60 {
		t.Errorf("timestamp TTL=%d want 60", msg.Answer[0].Header().Ttl)
	}
}

func TestHandler_Handle_Timestamp0(t *testing.T) {
	h := New(Config{Domain: "example.com"})
	req := new(dns.Msg)
	req.SetQuestion("timestamp0.example.com.", dns.TypeTXT)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("rcode=%d len=%d", msg.Rcode, len(msg.Answer))
	}
	if msg.Answer[0].Header().Ttl != 0 {
		t.Errorf("timestamp0 TTL=%d want 0", msg.Answer[0].Header().Ttl)
	}
}

func TestHandler_Handle_Protocol(t *testing.T) {
	h := New(Config{Domain: "example.com"})
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

func TestHandler_Handle_TTLN(t *testing.T) {
	h := New(Config{Domain: "example.com"})
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

func TestHandler_Handle_SizeN(t *testing.T) {
	h := New(Config{Domain: "example.com"})
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion("size-256.example.com.", dns.TypeTXT)
	req.SetEdns0(4096, false)
	msg := h.Handle(req, addr, "")
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("rcode=%d len=%d", msg.Rcode, len(msg.Answer))
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(packed) < 256 {
		t.Errorf("size-256 response wire size=%d want >= 256", len(packed))
	}
	// Invalid size-N should be NXDOMAIN
	req.SetQuestion("size-99.example.com.", dns.TypeTXT)
	msg2 := h.Handle(req, addr, "")
	if msg2.Rcode != dns.RcodeNameError {
		t.Errorf("size-99 (below min): rcode=%d want NXDOMAIN", msg2.Rcode)
	}
}

func TestHandler_Handle_QnameMin(t *testing.T) {
	h := New(Config{Domain: "example.com"})
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	for _, qname := range []string{"qname-min.example.com.", "a.b.c.qname-min.example.com."} {
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
