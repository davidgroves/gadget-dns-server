package handler

import (
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Gadget first labels under the zone.
const (
	LabelMyIP       = "myip"
	LabelMyPort     = "myport"
	LabelMyAddr     = "myaddr"
	LabelCounter    = "counter"
	LabelRandom     = "random"
	LabelEDNS       = "edns"
	LabelEDNSCS     = "edns-cs"
	LabelECS        = "ecs"
	LabelTimestamp  = "timestamp"
	LabelTimestamp0 = "timestamp0"
	LabelProtocol   = "protocol"
	LabelSigFail    = "sig-fail"
)

// Handler implements the gadget DNS responses (dnssrc-compatible).
type Handler struct {
	domain   string
	apexFQDN string
	// Zone apex config
	nsRecords []string
	serverIPs []net.IP
	soa       soaParams
	// Counter for "counter" endpoint
	counter atomic.Uint64
	// Optional signer (DNSSEC)
	signer Signer
	// Optional diag recorder (for token.diag.<zone>)
	diagRecorder DiagRecorder
}

// soaParams holds SOA fields.
type soaParams struct {
	mname   string
	rname   string
	serial  uint32
	refresh uint32
	retry   uint32
	expire  uint32
	minttl  uint32
}

// Config for the handler.
type Config struct {
	Domain       string
	NSRecords    []string
	ServerIPs    []net.IP
	SOAMname     string
	SOARname     string
	SOASerial    uint32
	SOARefresh   uint32
	SOARetry     uint32
	SOAExpire    uint32
	SOAMinttl    uint32
	Signer       Signer
	DiagRecorder DiagRecorder // optional: record *.diag.<zone> queries
}

// DiagRecorder records DNS queries for the diag dashboard (token.diag.<zone>).
type DiagRecorder interface {
	RecordDiag(token string, qname string, qtype uint16, clientAddr string, transport string)
}

// Signer can sign a response (add RRSIGs, NSEC, etc.).
type Signer interface {
	SignResponse(msg *dns.Msg, qname string, qtype uint16) error
}

// New creates a new Handler.
func New(cfg Config) *Handler {
	domain := strings.TrimSuffix(strings.ToLower(cfg.Domain), ".")
	apexFQDN := dns.Fqdn(domain)
	mname := cfg.SOAMname
	if mname == "" {
		mname = apexFQDN
	}
	rname := cfg.SOARname
	if rname == "" {
		rname = "hostmaster." + apexFQDN
	} else if !strings.Contains(rname, ".") {
		rname = rname + "." + apexFQDN
	}
	serial := cfg.SOASerial
	if serial == 0 {
		serial = 1
	}
	refresh := cfg.SOARefresh
	if refresh == 0 {
		refresh = 86400
	}
	retry := cfg.SOARetry
	if retry == 0 {
		retry = 7200
	}
	expire := cfg.SOAExpire
	if expire == 0 {
		expire = 3600000
	}
	minttl := cfg.SOAMinttl
	if minttl == 0 {
		minttl = 60
	}
	return &Handler{
		domain:       domain,
		apexFQDN:     apexFQDN,
		nsRecords:    cfg.NSRecords,
		serverIPs:    cfg.ServerIPs,
		signer:       cfg.Signer,
		diagRecorder: cfg.DiagRecorder,
		soa: soaParams{
			mname:   dns.Fqdn(mname),
			rname:   dns.Fqdn(rname),
			serial:  serial,
			refresh: refresh,
			retry:   retry,
			expire:  expire,
			minttl:  minttl,
		},
	}
}

// TransportWriter is optional: if the ResponseWriter implements it, Handle uses it for the protocol gadget.
type TransportWriter interface {
	dns.ResponseWriter
	Transport() string
}

// ServeDNS implements dns.Handler.
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	clientAddr := addrFromWriter(w)
	transport := ""
	if tw, ok := w.(TransportWriter); ok {
		transport = tw.Transport()
	}
	msg := h.Handle(r, clientAddr, transport)
	_ = w.WriteMsg(msg)
}

// Handle processes a query and returns a response. clientAddr is used for myip/myport/myaddr; transport for protocol gadget.
func (h *Handler) Handle(r *dns.Msg, clientAddr net.Addr, transport string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if len(r.Question) == 0 {
		msg.Rcode = dns.RcodeFormatError
		return msg
	}
	q := r.Question[0]
	qname := strings.TrimSuffix(strings.ToLower(q.Name), ".")

	// Must be under our zone
	if qname != h.domain && !strings.HasSuffix(qname, "."+h.domain) {
		msg.Rcode = dns.RcodeRefused
		return msg
	}

	// Zone apex
	if qname == h.domain {
		resp := h.handleApex(q.Name, q.Qtype, msg)
		if h.signer != nil {
			_ = h.signer.SignResponse(msg, q.Name, q.Qtype)
		}
		return resp
	}

	// Diag dashboard: <token>.diag.<zone> — record query and return TXT + A/AAAA.
	diagBase := ".diag." + h.domain
	if strings.HasSuffix(qname, diagBase) {
		tokenPart := strings.TrimSuffix(qname, diagBase)
		token := tokenPart
		if i := strings.LastIndex(tokenPart, "."); i >= 0 {
			token = tokenPart[i+1:]
		}
		if h.diagRecorder != nil && token != "" {
			h.diagRecorder.RecordDiag(token, q.Name, q.Qtype, clientAddr.String(), transport)
		}
		viewURL := "https://" + token + ".diag." + h.domain
		if q.Qtype == dns.TypeTXT {
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"View queries at " + viewURL},
			})
		}
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			for _, ip := range h.serverIPs {
				if q.Qtype == dns.TypeA && ip.To4() != nil {
					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   ip.To4(),
					})
				}
				if q.Qtype == dns.TypeAAAA && ip.To4() == nil {
					msg.Answer = append(msg.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: ip,
					})
				}
			}
		}
		if len(msg.Answer) > 0 && h.signer != nil {
			_ = h.signer.SignResponse(msg, q.Name, q.Qtype)
		}
		return msg
	}

	// QNAME minimization: *.qname-min.<zone> returns TXT with the exact received qname.
	qnameMinBase := "qname-min." + h.domain
	if qname == qnameMinBase || strings.HasSuffix(qname, "."+qnameMinBase) {
		if q.Qtype != dns.TypeTXT {
			msg.Rcode = dns.RcodeSuccess
			if h.signer != nil {
				_ = h.signer.SignResponse(msg, q.Name, q.Qtype)
			}
			return msg
		}
		receivedQname := q.Name
		if !strings.HasSuffix(receivedQname, ".") {
			receivedQname = receivedQname + "."
		}
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{"qname received: " + receivedQname},
		})
		if h.signer != nil {
			_ = h.signer.SignResponse(msg, q.Name, q.Qtype)
		}
		return msg
	}

	// First label under zone (e.g. myip.domain.com -> "myip")
	labels := strings.Split(qname, ".")
	var firstLabel string
	for i, l := range labels {
		if i+1 < len(labels) && strings.Join(labels[i+1:], ".") == h.domain {
			firstLabel = l
			break
		}
	}
	if firstLabel == "" {
		msg.Rcode = dns.RcodeNameError
		msg.Ns = []dns.RR{} // NSEC added by signer if DNSSEC
		if h.signer != nil {
			_ = h.signer.SignResponse(msg, q.Name, q.Qtype)
		}
		return msg
	}

	resp := h.handleGadget(q.Name, q.Qtype, firstLabel, r, clientAddr, transport, msg)
	if resp == nil {
		msg.Rcode = dns.RcodeNameError
		if h.signer != nil {
			_ = h.signer.SignResponse(msg, q.Name, q.Qtype)
		}
		return msg
	}
	if h.signer != nil {
		_ = h.signer.SignResponse(msg, q.Name, q.Qtype)
	}
	return msg
}

func (h *Handler) handleApex(name string, qtype uint16, msg *dns.Msg) *dns.Msg {
	switch qtype {
	case dns.TypeSOA:
		msg.Answer = append(msg.Answer, &dns.SOA{
			Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
			Ns:      h.soa.mname,
			Mbox:    h.soa.rname,
			Serial:  h.soa.serial,
			Refresh: h.soa.refresh,
			Retry:   h.soa.retry,
			Expire:  h.soa.expire,
			Minttl:  h.soa.minttl,
		})
		return msg
	case dns.TypeNS:
		if len(h.nsRecords) > 0 {
			for _, ns := range h.nsRecords {
				target := ns
				if !strings.HasSuffix(target, ".") {
					target = dns.Fqdn(ns)
				}
				msg.Answer = append(msg.Answer, &dns.NS{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
					Ns:  target,
				})
			}
			return msg
		}
	case dns.TypeA:
		for _, ip := range h.serverIPs {
			if ip4 := ip.To4(); ip4 != nil {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   ip4,
				})
			}
		}
		if len(msg.Answer) > 0 {
			return msg
		}
	case dns.TypeAAAA:
		for _, ip := range h.serverIPs {
			if ip.To4() == nil && len(ip) == 16 {
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: ip,
				})
			}
		}
		if len(msg.Answer) > 0 {
			return msg
		}
	}
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{h.soaRR(name)}
	return msg
}

func (h *Handler) soaRR(name string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      h.soa.mname,
		Mbox:    h.soa.rname,
		Serial:  h.soa.serial,
		Refresh: h.soa.refresh,
		Retry:   h.soa.retry,
		Expire:  h.soa.expire,
		Minttl:  h.soa.minttl,
	}
}

const maxTTL = 86400
const minSizeN = 128
const maxSizeN = 4096

// handleGadget returns the response for a gadget label; nil means NXDOMAIN.
func (h *Handler) handleGadget(name string, qtype uint16, label string, req *dns.Msg, clientAddr net.Addr, transport string, msg *dns.Msg) *dns.Msg {
	host, port := splitAddr(clientAddr)
	ttl := uint32(60)
	ttl0 := uint32(0)

	// size-N: response wire size approximately N bytes (128 <= N <= 4096).
	if strings.HasPrefix(label, "size-") {
		nStr := label[5:]
		n, err := strconv.ParseUint(nStr, 10, 32)
		if err != nil || n < minSizeN || n > maxSizeN {
			return nil
		}
		if qtype != dns.TypeTXT {
			msg.Rcode = dns.RcodeSuccess
			return msg
		}
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: []string{"size-" + nStr},
		})
		if msg.IsEdns0() == nil {
			msg.SetEdns0(4096, false)
		}
		packed, err := msg.Pack()
		if err != nil {
			return msg
		}
		baseSize := len(packed)
		if baseSize >= int(n) {
			return msg
		}
		paddingLen := int(n) - baseSize - 4
		if paddingLen <= 0 {
			return msg
		}
		opt := msg.IsEdns0()
		if opt != nil {
			opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, paddingLen)})
		}
		return msg
	}

	// Variable TTL: ttl-N.<zone> returns TXT with TTL = N seconds (0 <= N <= 86400).
	if strings.HasPrefix(label, "ttl-") {
		nStr := label[4:]
		n, err := strconv.ParseUint(nStr, 10, 32)
		if err != nil || n > maxTTL {
			return nil
		}
		if qtype != dns.TypeTXT {
			msg.Rcode = dns.RcodeSuccess
			return msg
		}
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(n)},
			Txt: []string{strconv.FormatInt(time.Now().Unix(), 10)},
		})
		return msg
	}

	switch label {
	case LabelMyIP:
		if qtype != dns.TypeA && qtype != dns.TypeAAAA {
			msg.Rcode = dns.RcodeSuccess
			return msg
		}
		ip := parseIP(host)
		if ip == nil {
			msg.Rcode = dns.RcodeServerFailure
			return msg
		}
		if qtype == dns.TypeA {
			if ip4 := ip.To4(); ip4 != nil {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   ip4,
				})
			} else {
				msg.Rcode = dns.RcodeSuccess
				return msg
			}
		} else {
			if ip.To4() == nil {
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
					AAAA: ip,
				})
			} else {
				msg.Rcode = dns.RcodeSuccess
				return msg
			}
		}
		return msg
	case LabelMyPort:
		if qtype != dns.TypeTXT {
			msg.Rcode = dns.RcodeSuccess
			return msg
		}
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: []string{port},
		})
		return msg
	case LabelMyAddr:
		if qtype != dns.TypeTXT {
			msg.Rcode = dns.RcodeSuccess
			return msg
		}
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: []string{host, port},
		})
		return msg
	case LabelCounter:
		if qtype != dns.TypeTXT {
			msg.Rcode = dns.RcodeSuccess
			return msg
		}
		n := h.counter.Add(1)
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: []string{strconv.FormatUint(n, 10)},
		})
		return msg
	case LabelRandom:
		if qtype == dns.TypeA {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   randomIPv4(),
			})
		} else if qtype == dns.TypeAAAA {
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: randomIPv6(),
			})
		} else if qtype == dns.TypeTXT {
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
				Txt: []string{randomTXT()},
			})
		} else {
			msg.Rcode = dns.RcodeSuccess
		}
		return msg
	case LabelEDNS:
		if qtype != dns.TypeTXT {
			msg.Rcode = dns.RcodeSuccess
			return msg
		}
		txt := ednsOptionsString(req)
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: []string{txt},
		})
		return msg
	case LabelEDNSCS, LabelECS:
		if qtype != dns.TypeTXT {
			msg.Rcode = dns.RcodeSuccess
			return msg
		}
		txt := ednsClientSubnetString(req)
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: []string{txt},
		})
		return msg
	case LabelTimestamp:
		if qtype != dns.TypeTXT {
			msg.Rcode = dns.RcodeSuccess
			return msg
		}
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: []string{strconv.FormatInt(time.Now().UnixMilli(), 10)},
		})
		return msg
	case LabelTimestamp0:
		if qtype != dns.TypeTXT {
			msg.Rcode = dns.RcodeSuccess
			return msg
		}
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl0},
			Txt: []string{strconv.FormatInt(time.Now().UnixMilli(), 10)},
		})
		return msg
	case LabelProtocol:
		if qtype != dns.TypeTXT {
			msg.Rcode = dns.RcodeSuccess
			return msg
		}
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: []string{transport},
		})
		return msg
	case LabelSigFail:
		// Intentionally broken for DNSSEC validation testing: validators should get SERVFAIL.
		if qtype == dns.TypeA {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   net.ParseIP("192.0.2.1"),
			})
		} else if qtype == dns.TypeTXT {
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
				Txt: []string{"validation failed if you see this"},
			})
		} else {
			msg.Rcode = dns.RcodeSuccess
		}
		return msg
	default:
		return nil
	}
}

func addrFromWriter(w dns.ResponseWriter) net.Addr {
	if w == nil {
		return nil
	}
	return w.RemoteAddr()
}

func splitAddr(addr net.Addr) (host, port string) {
	if addr == nil {
		return "", "0"
	}
	s := addr.String()
	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		return s[:idx], s[idx+1:]
	}
	return s, "0"
}

func parseIP(host string) net.IP {
	ip := net.ParseIP(host)
	if ip != nil {
		return ip
	}
	// Try stripping brackets for [::1]
	if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return net.ParseIP(host[1 : len(host)-1])
	}
	return nil
}

func ednsOptionsString(req *dns.Msg) string {
	opt := req.IsEdns0()
	if opt == nil {
		return ""
	}
	var parts []string
	for _, o := range opt.Option {
		parts = append(parts, o.String())
	}
	return strings.Join(parts, ",")
}

func ednsClientSubnetString(req *dns.Msg) string {
	opt := req.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		if subnet, ok := o.(*dns.EDNS0_SUBNET); ok {
			return subnet.Address.String() + "/" + strconv.Itoa(int(subnet.SourceNetmask))
		}
	}
	return ""
}

func randomIPv4() net.IP {
	return net.IPv4(10, byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)))
}

func randomIPv6() net.IP {
	ip := make(net.IP, 16)
	ip[0] = 0xfd
	for i := 1; i < 16; i++ {
		ip[i] = byte(rand.Intn(256))
	}
	return ip
}

const randomChars = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomTXT() string {
	n := 8 + rand.Intn(16)
	b := make([]byte, n)
	for i := range b {
		b[i] = randomChars[rand.Intn(len(randomChars))]
	}
	return string(b)
}
