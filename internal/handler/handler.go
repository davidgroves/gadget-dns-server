package handler

import (
	"encoding/hex"
	"fmt"
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
	LabelMyIP            = "myip"
	LabelIP              = "ip" // alias for myip
	LabelMyPort          = "myport"
	LabelPort            = "port" // alias for myport
	LabelMyAddr          = "myaddr"
	LabelAddr            = "addr"         // alias for myaddr
	LabelConnection      = "connection"   // URL-like: doh://ip:port or dot://[ipv6]:port
	LabelMyConnection    = "myconnection" // alias for connection
	LabelCounter         = "counter"
	LabelRandom          = "random"
	LabelEDNS            = "edns"
	LabelEDNSCS          = "edns-cs"
	LabelECS             = "ecs"
	LabelCookie          = "cookie"
	LabelProtocol        = "protocol"
	LabelDnssecFailed    = "dnssec-failed" // subdomain: <fail-type>.dnssec-failed.<zone>
	LabelSigFail         = "sig-fail"
	LabelRRSIGExpired    = "rrsig-expired"
	LabelRRSIGFuture     = "rrsig-future"
	LabelNSECMissing     = "nsec-missing"
	LabelNSECWrongNext   = "nsec-wrong-next"
	LabelRRSIGWrongAlg   = "rrsig-wrong-alg"
	LabelRRSIGWrongRRset = "rrsig-wrong-rrset"
	LabelRRSIGMissing    = "rrsig-missing"
	LabelNSEC3Instead    = "nsec3-instead"
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
	signer     Signer
	publishCDS bool
	// Optional diag recorder (for token.diag.<zone>)
	diagRecorder DiagRecorder
	// Optional entropy recorder (for *.entropy.<zone>)
	entropyRecorder EntropyRecorder
	// Optional qname-min recorder (for *.qname-min.<zone> minimization sequence)
	qnameMinRecorder QnameMinRecorder
	// Optional metrics recorder (e.g. Prometheus)
	metricsRecorder MetricsRecorder
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
	Domain           string
	NSRecords        []string
	ServerIPs        []net.IP
	SOAMname         string
	SOARname         string
	SOASerial        uint32
	SOARefresh       uint32
	SOARetry         uint32
	SOAExpire        uint32
	SOAMinttl        uint32
	Signer           Signer
	PublishCDS       bool             // serve CDS at apex for parent DS (when DNSSEC enabled)
	DiagRecorder     DiagRecorder     // optional: record *.diag.<zone> queries
	EntropyRecorder  EntropyRecorder  // optional: record *.entropy.<zone> for port/ID entropy
	QnameMinRecorder QnameMinRecorder // optional: record *.qname-min.<zone> for minimization sequence
	MetricsRecorder  MetricsRecorder  // optional: record request metrics (e.g. Prometheus)
}

// EntropyRecorder records DNS queries for entropy checks (*.entropy.<zone>). qname is QNAME as received (for 0x20).
type EntropyRecorder interface {
	RecordEntropy(runId string, clientAddr string, sourcePort int, transactionID uint16, qname string)
}

// DiagRecorder records DNS queries for the diag dashboard (token.diag.<zone>).
// req and resp are the request and full response messages (wire capture).
type DiagRecorder interface {
	RecordDiag(token string, req *dns.Msg, resp *dns.Msg, clientAddr string, transport string)
}

// RelatedRecorder optionally records related in-zone queries (e.g. DNSKEY from same client) for the diag dashboard.
// Implemented by the same adapter as DiagRecorder; called only when the client is in an active diag session.
type RelatedRecorder interface {
	RecordRelatedIfInSession(clientAddr string, req *dns.Msg, resp *dns.Msg, transport string)
}

// Signer can sign a response (add RRSIGs, NSEC, etc.).
// DNSSEC data is only added when the request has EDNS DO bit set or qtype is RRSIG/NSEC/NSEC3/DNSKEY/DS.
type Signer interface {
	SignResponse(msg *dns.Msg, req *dns.Msg) error
}

// CDSProvider can supply the zone's CDS record (for parent DS). Implemented by dnssec.Signer.
type CDSProvider interface {
	CDSRecord() *dns.CDS
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
	nsRecords := cfg.NSRecords
	if len(nsRecords) == 0 && domain != "" {
		// Default apex NS to zone name (in-bailiwick) so NS is always served when domain is set.
		nsRecords = []string{apexFQDN}
	}
	return &Handler{
		domain:           domain,
		apexFQDN:         apexFQDN,
		nsRecords:        nsRecords,
		serverIPs:        cfg.ServerIPs,
		signer:           cfg.Signer,
		publishCDS:       cfg.PublishCDS,
		diagRecorder:     cfg.DiagRecorder,
		entropyRecorder:  cfg.EntropyRecorder,
		qnameMinRecorder: cfg.QnameMinRecorder,
		metricsRecorder:  cfg.MetricsRecorder,
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

// MetricsRecorder records DNS request metrics (e.g. for Prometheus). Optional.
type MetricsRecorder interface {
	RecordDNS(transport, qtype, rcode string, duration time.Duration)
}

// ServeDNS implements dns.Handler.
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	clientAddr := addrFromWriter(w)
	transport := ""
	if tw, ok := w.(TransportWriter); ok {
		transport = tw.Transport()
	}
	msg := h.Handle(r, clientAddr, transport)
	if msg == nil {
		msg = new(dns.Msg)
		msg.SetRcode(r, dns.RcodeServerFailure)
	}
	if h.metricsRecorder != nil {
		qtypeStr := "UNKNOWN"
		if len(r.Question) > 0 {
			qtypeStr = dns.TypeToString[r.Question[0].Qtype]
			if qtypeStr == "" {
				qtypeStr = fmt.Sprintf("TYPE%d", r.Question[0].Qtype)
			}
		}
		rcodeStr := dns.RcodeToString[msg.Rcode]
		if rcodeStr == "" {
			rcodeStr = fmt.Sprintf("RCODE%d", msg.Rcode)
		}
		h.metricsRecorder.RecordDNS(transport, qtypeStr, rcodeStr, time.Since(start))
	}
	// Optionally record related in-zone queries (e.g. DNSKEY) for diag when client is in a diag session
	if h.diagRecorder != nil && msg.Rcode == dns.RcodeSuccess && len(r.Question) > 0 {
		qname := strings.TrimSuffix(strings.ToLower(r.Question[0].Name), ".")
		diagBase := ".diag." + h.domain
		inZone := qname == h.domain || strings.HasSuffix(qname, "."+h.domain)
		notDiag := !strings.HasSuffix(qname, diagBase) && qname != "diag."+h.domain
		if inZone && notDiag {
			if rec, ok := h.diagRecorder.(RelatedRecorder); ok {
				rec.RecordRelatedIfInSession(clientAddr.String(), r, msg, transport)
			}
		}
	}
	h.FinalizeResponse(r, msg)
	_ = w.WriteMsg(msg)
}

// FinalizeResponse applies post-Handle tweaks: EDNS OPT, DNSKEY TC, and set-cookie/set-ede/set-flags/set-rcode/set-status/set-id from the first label.
func (h *Handler) FinalizeResponse(r *dns.Msg, msg *dns.Msg) {
	// RFC 6891 §7: if the request had EDNS, include OPT in the response (skip for BADVERS — we already set OPT in Handle)
	udpSize := uint16(512)
	if reqOpt := r.IsEdns0(); reqOpt != nil && msg.Rcode != dns.RcodeBadVers {
		udpSize = reqOpt.UDPSize()
		if udpSize == 0 {
			udpSize = 4096
		}
		if udpSize > 4096 {
			udpSize = 4096
		}
		msg.SetEdns0(udpSize, reqOpt.Do())
	}
	// RFC 1035 §4.2: DNSKEY response often exceeds 512 bytes; set TC so client retries over TCP
	if len(r.Question) > 0 {
		q := r.Question[0]
		qname := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		if qname == h.domain && q.Qtype == dns.TypeDNSKEY && udpSize <= 512 {
			msg.Truncated = true
		}
	}
	// set-answer-* / set-answer-plaintext-* (A and TXT only), then set-cookie-*, set-ede-*, etc. from parsed set-options (stacked)
	if len(r.Question) > 0 {
		q := r.Question[0]
		qnameLower := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		qnameFQDN := q.Name
		if !strings.HasSuffix(qnameFQDN, ".") {
			qnameFQDN = qnameFQDN + "."
		}
		var setOptions []string
		if strings.HasSuffix(qnameLower, ".diag."+h.domain) {
			if parsed, ok := parseDiag(qnameLower, h.domain); ok {
				setOptions = parsed.SetOptions
			}
		} else {
			if parsed, ok := parseTopLevel(qnameLower, h.domain); ok {
				setOptions = parsed.SetOptions
			}
		}
		if len(setOptions) > 0 {
			applySetAnswer(msg, setOptions, qnameFQDN, q.Qtype)
			applySetModifiers(h, r, msg, setOptions)
		}
	}
}

// Handle processes a query and returns a response. clientAddr is used for myip/myport/myaddr; transport for protocol gadget.
func (h *Handler) Handle(r *dns.Msg, clientAddr net.Addr, transport string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	// RFC 6891 §7: if request has OPT with version != 0, MUST return RCODE BADVERS and OPT indicating highest version we support (0)
	if opt := r.IsEdns0(); opt != nil {
		version := (opt.Hdr.Ttl >> 16) & 0xFF
		if version != 0 {
			msg.Rcode = dns.RcodeBadVers
			msg.SetEdns0(4096, false)
			return msg
		}
	}

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
			_ = h.signer.SignResponse(msg, r)
		}
		return resp
	}

	// www.<zone> — A/AAAA for the webserver (same IPs as apex)
	wwwHost := "www." + h.domain
	if qname == wwwHost {
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			addAaaaFromIPs(msg, q.Name, q.Qtype, h.serverIPs)
		}
		h.ensureSignedOrNodata(msg, r)
		return msg
	}

	// Diag dashboard: exact diag.<zone> — A/AAAA for the host; <token>.diag.<zone> — record and return TXT + A/AAAA.
	diagHost := "diag." + h.domain
	if qname == diagHost {
		viewURL := "https://diag." + h.domain + "/<token>"
		if q.Qtype == dns.TypeTXT {
			appendTXT(msg, q.Name, 0, "View dashboard at "+viewURL)
		}
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			addAaaaFromIPs(msg, q.Name, q.Qtype, h.serverIPs)
		}
		h.ensureSignedOrNodata(msg, r)
		return msg
	}
	diagBase := ".diag." + h.domain
	if strings.HasSuffix(qname, diagBase) {
		parsed, _ := parseDiag(qname, h.domain) // we already matched *.diag.<zone>
		token := parsed.Token
		if parsed.Gadget != "" {
			// Gadget under diag: run gadget and return its response; still record to diag
			resp := h.handleGadget(q.Name, q.Qtype, parsed.Gadget, r, clientAddr, transport, msg)
			if resp == nil {
				msg.Rcode = dns.RcodeNameError
				msg.Ns = []dns.RR{h.soaRR(h.apexFQDN)}
				if h.signer != nil {
					_ = h.signer.SignResponse(msg, r)
				}
				if h.diagRecorder != nil && token != "" {
					h.diagRecorder.RecordDiag(token, r, msg, clientAddr.String(), transport)
				}
				return msg
			}
			if h.signer != nil {
				_ = h.signer.SignResponse(msg, r)
			}
			if h.diagRecorder != nil && token != "" {
				h.diagRecorder.RecordDiag(token, r, msg, clientAddr.String(), transport)
			}
			return msg
		}
		// Token-only diag: TXT + A/AAAA and record
		viewURL := "https://diag." + h.domain + "/" + token
		if q.Qtype == dns.TypeTXT {
			appendTXT(msg, q.Name, 0, "View queries at "+viewURL)
		}
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			addAaaaFromIPs(msg, q.Name, q.Qtype, h.serverIPs)
		}
		h.ensureSignedOrNodata(msg, r)
		if h.diagRecorder != nil && token != "" {
			h.diagRecorder.RecordDiag(token, r, msg, clientAddr.String(), transport)
		}
		return msg
	}

	// help.<zone> — TXT with link to docs (https://www.<zone>).
	helpHost := "help." + h.domain
	if qname == helpHost {
		docsURL := "https://www." + h.domain
		if q.Qtype == dns.TypeTXT {
			appendTXT(msg, q.Name, 3600, docsURL)
		}
		h.ensureSignedOrNodata(msg, r)
		return msg
	}

	// Entropy check: *.entropy.<zone> — A/AAAA for browser requests; record source port and transaction ID.
	entropyBase := ".entropy." + h.domain
	if qname == "entropy."+h.domain || strings.HasSuffix(qname, entropyBase) {
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			addAaaaFromIPs(msg, q.Name, q.Qtype, h.serverIPs)
		}
		h.ensureSignedOrNodata(msg, r)
		if h.entropyRecorder != nil && (qname == "entropy."+h.domain || strings.HasSuffix(qname, entropyBase)) {
			leftLabel := strings.TrimSuffix(qname, entropyBase)
			if idx := strings.LastIndex(leftLabel, "."); idx >= 0 {
				leftLabel = leftLabel[idx+1:]
			}
			if leftLabel != "" {
				_, portStr := splitAddr(clientAddr)
				sourcePort, _ := strconv.Atoi(portStr)
				runId := parseEntropyRunId(leftLabel)
				h.entropyRecorder.RecordEntropy(runId, clientAddr.String(), sourcePort, r.Id, q.Name)
			}
		}
		return msg
	}

	// In-zone NS record targets (glue): serve A/AAAA so resolvers can reach nameservers.
	for _, ns := range h.nsRecords {
		target := ns
		if !strings.HasSuffix(target, ".") {
			target = dns.Fqdn(ns)
		}
		targetName := strings.TrimSuffix(strings.ToLower(target), ".")
		if targetName != "" && (targetName == h.domain || strings.HasSuffix(targetName, "."+h.domain)) && qname == targetName {
			if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
				addAaaaFromIPs(msg, q.Name, q.Qtype, h.serverIPs)
			}
			h.ensureSignedOrNodata(msg, r)
			return msg
		}
	}

	// QNAME minimization: *.qname-min.<zone> returns TXT with the exact received qname and (if recorder set) the sequence of qnames seen from this client (RFC 7816).
	qnameMinBase := "qname-min." + h.domain
	if qname == qnameMinBase || strings.HasSuffix(qname, "."+qnameMinBase) {
		clientIP, _ := splitAddr(clientAddr)
		if h.qnameMinRecorder != nil {
			h.qnameMinRecorder.Record(clientIP, q.Name)
		}
		if q.Qtype != dns.TypeTXT {
			msg.Rcode = dns.RcodeSuccess
			msg.Ns = []dns.RR{h.soaRR(h.apexFQDN)}
			if h.signer != nil {
				_ = h.signer.SignResponse(msg, r)
			}
			return msg
		}
		receivedQname := q.Name
		if !strings.HasSuffix(receivedQname, ".") {
			receivedQname = receivedQname + "."
		}
		txtStrings := []string{"qname received: " + receivedQname}
		if h.qnameMinRecorder != nil {
			seq := h.qnameMinRecorder.GetRecentSequence(clientIP)
			if len(seq) > 0 {
				if len(seq) == 1 {
					txtStrings = append(txtStrings, "minimization sequence (single query observed): 1. "+seq[0])
				} else {
					line := "minimization sequence (oldest first):"
					for i, qn := range seq {
						line += fmt.Sprintf(" %d. %s", i+1, qn)
						if i < len(seq)-1 {
							line += ","
						}
					}
					txtStrings = append(txtStrings, line)
				}
			}
		}
		appendTXTStrings(msg, q.Name, 0, txtStrings)
		if h.signer != nil {
			_ = h.signer.SignResponse(msg, r)
		}
		return msg
	}

	// DNSSEC fail-case subdomain: <fail-type>.dnssec-failed.<zone> (e.g. sig-fail.dnssec-failed.dnssrc.fibrecat.org)
	dnssecFailedSuffix := ".dnssec-failed." + h.domain
	if qname == "dnssec-failed."+h.domain || strings.HasSuffix(qname, dnssecFailedSuffix) {
		resp := h.handleDnssecFailed(q.Name, q.Qtype, r, clientAddr, transport, msg)
		if resp == nil {
			msg.Rcode = dns.RcodeNameError
			msg.Ns = []dns.RR{h.soaRR(h.apexFQDN)}
			if h.signer != nil {
				_ = h.signer.SignResponse(msg, r)
			}
			return msg
		}
		if h.signer != nil {
			_ = h.signer.SignResponse(msg, r)
		}
		return msg
	}

	// Top-level: parse prefix into set-options and gadget
	parsed, ok := parseTopLevel(qname, h.domain)
	if !ok {
		msg.Rcode = dns.RcodeNameError
		msg.Ns = []dns.RR{h.soaRR(h.apexFQDN)} // RFC 2308: NXDOMAIN includes SOA; signer adds NSEC
		if h.signer != nil {
			_ = h.signer.SignResponse(msg, r)
		}
		return msg
	}
	if parsed.Gadget == "" && len(parsed.SetOptions) == 0 {
		msg.Rcode = dns.RcodeNameError
		msg.Ns = []dns.RR{h.soaRR(h.apexFQDN)}
		if h.signer != nil {
			_ = h.signer.SignResponse(msg, r)
		}
		return msg
	}
	if parsed.Gadget == "" && len(parsed.SetOptions) > 0 {
		// Set-options only: validate each; NXDOMAIN if any invalid, else NODATA (modifiers applied in FinalizeResponse)
		for _, label := range parsed.SetOptions {
			if !isValidSetOption(label) {
				msg.Rcode = dns.RcodeNameError
				msg.Ns = []dns.RR{h.soaRR(h.apexFQDN)}
				if h.signer != nil {
					_ = h.signer.SignResponse(msg, r)
				}
				return msg
			}
		}
		h.setNodataSOA(msg)
		if h.signer != nil {
			_ = h.signer.SignResponse(msg, r)
		}
		return msg
	}

	resp := h.handleGadget(q.Name, q.Qtype, parsed.Gadget, r, clientAddr, transport, msg)
	if resp == nil {
		msg.Rcode = dns.RcodeNameError
		msg.Ns = []dns.RR{h.soaRR(h.apexFQDN)} // RFC 2308: NXDOMAIN includes SOA; signer adds NSEC
		if h.signer != nil {
			_ = h.signer.SignResponse(msg, r)
		}
		return msg
	}
	if h.signer != nil {
		_ = h.signer.SignResponse(msg, r)
	}
	return msg
}

func (h *Handler) handleApex(name string, qtype uint16, msg *dns.Msg) *dns.Msg {
	switch qtype {
	case dns.TypeSOA:
		msg.Answer = append(msg.Answer, &dns.SOA{
			Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 0},
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
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 0},
					Ns:  target,
				})
			}
			return msg
		}
	case dns.TypeCDS:
		if h.publishCDS && h.signer != nil {
			if p, ok := h.signer.(CDSProvider); ok {
				if cds := p.CDSRecord(); cds != nil {
					cds.Hdr.Name = name
					cds.Hdr.Rrtype = dns.TypeCDS
					cds.Hdr.Class = dns.ClassINET
					cds.Hdr.Ttl = 0
					msg.Answer = append(msg.Answer, cds)
					return msg
				}
			}
		}
	case dns.TypeDNSKEY:
		// Return without SOA in Authority so SignResponse adds only DNSKEY to Answer.
		// Keeps response under 512 bytes so validators with EDNS0 512 get full DNSKEY RRset + both RRSIGs (no truncation).
		return msg
	case dns.TypeA:
		addAaaaFromIPs(msg, name, dns.TypeA, h.serverIPs)
		if len(msg.Answer) > 0 {
			return msg
		}
	case dns.TypeAAAA:
		addAaaaFromIPs(msg, name, dns.TypeAAAA, h.serverIPs)
		if len(msg.Answer) > 0 {
			return msg
		}
	}
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{h.soaRR(h.apexFQDN)} // RFC 2308 §2.2: NODATA SOA owner is zone apex
	return msg
}

func (h *Handler) soaRR(name string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 0},
		Ns:      h.soa.mname,
		Mbox:    h.soa.rname,
		Serial:  h.soa.serial,
		Refresh: h.soa.refresh,
		Retry:   h.soa.retry,
		Expire:  h.soa.expire,
		Minttl:  h.soa.minttl,
	}
}

// setNodataSOA sets msg to NODATA (Rcode Success, SOA in Ns). Use for TXT-only gadgets when qtype != TXT.
func (h *Handler) setNodataSOA(msg *dns.Msg) {
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{h.soaRR(h.apexFQDN)}
}

// appendTXT appends a single TXT RR to msg.Answer with one string value.
func appendTXT(msg *dns.Msg, name string, ttl uint32, value string) {
	msg.Answer = append(msg.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
		Txt: []string{value},
	})
}

// appendTXTStrings appends a single TXT RR to msg.Answer with multiple string values (e.g. myaddr).
func appendTXTStrings(msg *dns.Msg, name string, ttl uint32, values []string) {
	msg.Answer = append(msg.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
		Txt: values,
	})
}

// addAaaaFromIPs appends A and/or AAAA RRs from ips to msg.Answer. qtype is dns.TypeA, dns.TypeAAAA, or 0 for both.
func addAaaaFromIPs(msg *dns.Msg, name string, qtype uint16, ips []net.IP) {
	for _, ip := range ips {
		if (qtype == dns.TypeA || qtype == 0) && ip.To4() != nil {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
				A:   ip.To4(),
			})
		}
		if (qtype == dns.TypeAAAA || qtype == 0) && ip.To4() == nil && len(ip) == 16 {
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
				AAAA: ip,
			})
		}
	}
}

// ensureSignedOrNodata sets NODATA (SOA in Ns) if msg has no answer, then signs if signer is set.
func (h *Handler) ensureSignedOrNodata(msg *dns.Msg, r *dns.Msg) {
	if len(msg.Answer) == 0 {
		msg.Rcode = dns.RcodeSuccess
		msg.Ns = []dns.RR{h.soaRR(h.apexFQDN)}
	}
	if h.signer != nil {
		_ = h.signer.SignResponse(msg, r)
	}
}

const maxTTL = 86400
const minSizeN = 128
const maxSizeN = 4096
const maxDelayMs = 300000 // 5 minutes

// handleGadget returns the response for a gadget label; nil means NXDOMAIN.
func (h *Handler) handleGadget(name string, qtype uint16, label string, req *dns.Msg, clientAddr net.Addr, transport string, msg *dns.Msg) *dns.Msg {
	host, port := splitAddr(clientAddr)
	ttl := uint32(0) // no caching for gadget data; only timestamp-N/ttl-N use non-zero TTL

	// set-cookie-<hex>: force cookie in response (applied in FinalizeResponse). Value must be valid hex (even length).
	if strings.HasPrefix(label, prefixSetCookie) {
		if !isValidCookieHex(label[len(prefixSetCookie):]) {
			return nil
		}
		h.setNodataSOA(msg)
		return msg
	}
	// set-ede-<number>[-<string>]: force EDE in response (applied in FinalizeResponse).
	if strings.HasPrefix(label, prefixSetEDE) {
		if _, _, ok := parseSetEDELabel(label); !ok {
			return nil
		}
		h.setNodataSOA(msg)
		return msg
	}
	// set-flags-<bitmask>: set response header flags (applied in FinalizeResponse).
	if strings.HasPrefix(label, prefixSetFlags) {
		rest := label[len(prefixSetFlags):]
		if _, ok := parseFlagsBitmask(rest); !ok {
			return nil
		}
		h.setNodataSOA(msg)
		return msg
	}
	// set-rcode-<value> / set-status-<value>: set response RCODE (applied in FinalizeResponse).
	if strings.HasPrefix(label, prefixSetRcode) || strings.HasPrefix(label, prefixSetStatus) {
		rest := label
		if strings.HasPrefix(label, prefixSetRcode) {
			rest = label[len(prefixSetRcode):]
		} else {
			rest = label[len(prefixSetStatus):]
		}
		if _, ok := parseRcodeValue(rest); !ok {
			return nil
		}
		h.setNodataSOA(msg)
		return msg
	}
	// set-id-<value>: set response transaction ID (applied in FinalizeResponse).
	if strings.HasPrefix(label, prefixSetID) {
		rest := label[len(prefixSetID):]
		if _, ok := parseSetIDValue(rest); !ok {
			return nil
		}
		h.setNodataSOA(msg)
		return msg
	}

	// size-N: response wire size approximately N bytes (128 <= N <= 4096).
	if strings.HasPrefix(label, "size-") {
		nStr := label[5:]
		n, err := strconv.ParseUint(nStr, 10, 32)
		if err != nil || n < minSizeN || n > maxSizeN {
			return nil
		}
		if qtype != dns.TypeTXT {
			h.setNodataSOA(msg)
			return msg
		}
		appendTXT(msg, name, ttl, "size-"+nStr)
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

	// delay-N or delay-X-Y: delay response by N ms or random between X and Y ms.
	if strings.HasPrefix(label, "delay-") {
		rest := label[6:]
		if rest == "" {
			return nil
		}
		var d time.Duration
		if strings.Contains(rest, "-") {
			parts := strings.SplitN(rest, "-", 2)
			x, err1 := strconv.ParseUint(parts[0], 10, 32)
			y, err2 := strconv.ParseUint(parts[1], 10, 32)
			if err1 != nil || err2 != nil || x > y || y > maxDelayMs {
				return nil
			}
			if y > x {
				d = time.Duration(x+uint64(rand.Intn(int(y-x+1)))) * time.Millisecond
			} else {
				d = time.Duration(x) * time.Millisecond
			}
		} else {
			n, err := strconv.ParseUint(rest, 10, 32)
			if err != nil || n > maxDelayMs {
				return nil
			}
			d = time.Duration(n) * time.Millisecond
		}
		time.Sleep(d)
		if qtype != dns.TypeTXT {
			h.setNodataSOA(msg)
			return msg
		}
		appendTXT(msg, name, ttl, fmt.Sprintf("delayed %v", d))
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
			h.setNodataSOA(msg)
			return msg
		}
		appendTXT(msg, name, uint32(n), strconv.FormatInt(time.Now().Unix(), 10))
		return msg
	}

	// timestamp-N.<zone> returns TXT with current time in milliseconds and TTL = N (0 <= N <= 86400).
	if strings.HasPrefix(label, "timestamp-") {
		nStr := label[len("timestamp-"):]
		n, err := strconv.ParseUint(nStr, 10, 32)
		if err != nil || n > maxTTL {
			return nil
		}
		if qtype != dns.TypeTXT {
			h.setNodataSOA(msg)
			return msg
		}
		appendTXT(msg, name, uint32(n), strconv.FormatInt(time.Now().UnixMilli(), 10))
		return msg
	}

	switch label {
	case LabelMyIP, LabelIP:
		ip := parseIP(host)
		if ip == nil {
			msg.Rcode = dns.RcodeServerFailure
			return msg
		}
		if qtype == dns.TypeTXT {
			appendTXT(msg, name, ttl, ip.String())
			return msg
		}
		// Always return both A and AAAA so DNSSEC NSEC bitmap is consistent (no NODATA for A/AAAA).
		if qtype == dns.TypeA || qtype == dns.TypeAAAA {
			if ip4 := ip.To4(); ip4 != nil {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   ip4,
				})
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
					AAAA: net.IPv6zero, // placeholder when client is IPv4-only
				})
			} else {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   net.IPv4zero, // placeholder when client is IPv6-only
				})
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
					AAAA: ip,
				})
			}
			return msg
		}
		h.setNodataSOA(msg)
		return msg
	case LabelMyPort, LabelPort:
		if qtype != dns.TypeTXT {
			h.setNodataSOA(msg)
			return msg
		}
		appendTXT(msg, name, ttl, port)
		return msg
	case LabelMyAddr, LabelAddr:
		if qtype != dns.TypeTXT {
			h.setNodataSOA(msg)
			return msg
		}
		appendTXTStrings(msg, name, ttl, []string{host, port})
		return msg
	case LabelConnection, LabelMyConnection:
		if qtype != dns.TypeTXT {
			h.setNodataSOA(msg)
			return msg
		}
		appendTXT(msg, name, ttl, connectionURL(transport, host, port))
		return msg
	case LabelCounter:
		if qtype != dns.TypeTXT {
			h.setNodataSOA(msg)
			return msg
		}
		n := h.counter.Add(1)
		appendTXT(msg, name, ttl, strconv.FormatUint(n, 10))
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
			appendTXT(msg, name, ttl, randomTXT())
		} else {
			h.setNodataSOA(msg)
		}
		return msg
	case LabelEDNS:
		if qtype != dns.TypeTXT {
			h.setNodataSOA(msg)
			return msg
		}
		appendTXT(msg, name, ttl, ednsOptionsString(req))
		return msg
	case LabelEDNSCS, LabelECS:
		if qtype != dns.TypeTXT {
			h.setNodataSOA(msg)
			return msg
		}
		appendTXT(msg, name, ttl, ednsClientSubnetString(req))
		return msg
	case LabelCookie:
		if qtype != dns.TypeTXT {
			h.setNodataSOA(msg)
			return msg
		}
		appendTXT(msg, name, ttl, ednsCookieString(req))
		return msg
	case LabelProtocol:
		if qtype != dns.TypeTXT {
			h.setNodataSOA(msg)
			return msg
		}
		appendTXT(msg, name, ttl, transport)
		return msg
	// DNSSEC fail-case gadgets under dnssec-failed.<zone>: <fail-type>.dnssec-failed.<zone>
	case LabelDnssecFailed:
		return h.handleDnssecFailed(name, qtype, req, clientAddr, transport, msg)
	default:
		return nil
	}
}

// handleDnssecFailed handles <fail-type>.dnssec-failed.<zone>; failType is the first label of the qname.
func (h *Handler) handleDnssecFailed(name string, qtype uint16, req *dns.Msg, clientAddr net.Addr, transport string, msg *dns.Msg) *dns.Msg {
	nameTrim := strings.TrimSuffix(strings.ToLower(name), ".")
	parts := strings.SplitN(nameTrim, ".", 2)
	if len(parts) < 2 {
		return nil
	}
	failType := parts[0]
	ttl := uint32(0)
	switch failType {
	case LabelSigFail:
		if qtype == dns.TypeA {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   net.ParseIP("192.0.2.1"),
			})
		} else if qtype == dns.TypeTXT {
			appendTXT(msg, name, ttl, "validation failed if you see this")
		} else {
			h.setNodataSOA(msg)
		}
		return msg
	case LabelRRSIGExpired, LabelRRSIGFuture, LabelRRSIGWrongAlg, LabelRRSIGWrongRRset, LabelRRSIGMissing:
		if qtype == dns.TypeA {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   net.ParseIP("192.0.2.1"),
			})
		} else if qtype == dns.TypeTXT {
			appendTXT(msg, name, ttl, "DNSSEC fail test")
		} else {
			h.setNodataSOA(msg)
		}
		return msg
	case LabelNSECMissing, LabelNSECWrongNext, LabelNSEC3Instead:
		h.setNodataSOA(msg)
		return msg
	default:
		return nil
	}
}

// firstLabelUnderZone returns the effective "first label" under the zone for qname (last label of prefix).
// Deprecated: new code should use parseTopLevel for set-options and gadget parsing.
// Kept for backward compatibility with tests; implemented in terms of parseTopLevel.
func firstLabelUnderZone(qname, domain string) string {
	parsed, ok := parseTopLevel(qname, domain)
	if !ok {
		return ""
	}
	if parsed.Gadget != "" {
		return parsed.Gadget
	}
	if len(parsed.SetOptions) > 0 {
		return parsed.SetOptions[len(parsed.SetOptions)-1]
	}
	return ""
}

const (
	prefixSetCookie          = "set-cookie-"
	prefixSetEDE             = "set-ede-"
	prefixSetFlags           = "set-flags-"
	prefixSetRcode           = "set-rcode-"
	prefixSetStatus          = "set-status-"
	prefixSetID              = "set-id-"
	prefixSetTTL             = "set-ttl-"
	prefixSetAnswer          = "set-answer-"
	prefixSetAnswerPlaintext = "set-answer-plaintext-"
)

// applySetAnswer replaces msg.Answer with A or TXT records from set-answer-* / set-answer-plaintext-* options.
// Only applies when qtype is A or TXT. Supports only A and TXT record types. Multiple set-answer-* values
// produce multiple A records; multiple set-answer-plaintext-* values produce one TXT RR with multiple strings.
func applySetAnswer(msg *dns.Msg, setOptions []string, qname string, qtype uint16) {
	if qtype != dns.TypeA && qtype != dns.TypeTXT {
		return
	}
	var aIPs []net.IP
	var txtStrings []string
	for _, label := range setOptions {
		if strings.HasPrefix(label, prefixSetAnswerPlaintext) {
			if qtype != dns.TypeTXT {
				continue
			}
			val := label[len(prefixSetAnswerPlaintext):]
			txtStrings = append(txtStrings, val)
			continue
		}
		if strings.HasPrefix(label, prefixSetAnswer) {
			if qtype != dns.TypeA {
				continue
			}
			ip := parseSetAnswerAValue(label)
			if ip != nil {
				aIPs = append(aIPs, ip)
			}
		}
	}
	if qtype == dns.TypeA && len(aIPs) > 0 {
		msg.Answer = nil
		msg.Ns = nil
		for _, ip := range aIPs {
			if ip4 := ip.To4(); ip4 != nil {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
					A:   ip4,
				})
			}
		}
		msg.Rcode = dns.RcodeSuccess
	}
	if qtype == dns.TypeTXT && len(txtStrings) > 0 {
		msg.Answer = nil
		msg.Ns = nil
		appendTXTStrings(msg, qname, 0, txtStrings)
		msg.Rcode = dns.RcodeSuccess
	}
}

// parseSetAnswerAValue parses set-answer-<a>-<b>-<c>-<d> and returns net.IPv4(a,b,c,d) or nil.
func parseSetAnswerAValue(label string) net.IP {
	if !strings.HasPrefix(label, prefixSetAnswer) || strings.HasPrefix(label, prefixSetAnswerPlaintext) {
		return nil
	}
	rest := label[len(prefixSetAnswer):]
	parts := strings.Split(rest, "-")
	if len(parts) != 4 {
		return nil
	}
	var octets [4]byte
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil
		}
		octets[i] = byte(n)
	}
	return net.IPv4(octets[0], octets[1], octets[2], octets[3])
}

// applySetModifiers applies each set-option (set-cookie-*, set-ede-*, set-flags-*, set-rcode-*, set-status-*, set-id-*, set-ttl-*, set-answer-*) to msg.
// set-answer-* is applied earlier (in FinalizeResponse before this) so that set-ttl applies to the new Answer RRs.
// Multiple options are applied in order so that e.g. set-cookie and set-ttl can be stacked.
func applySetModifiers(h *Handler, r *dns.Msg, msg *dns.Msg, setOptions []string) {
	ensureOPT := func() {
		if msg.IsEdns0() == nil {
			msg.SetEdns0(4096, false)
		}
	}
	for _, label := range setOptions {
		if strings.HasPrefix(label, prefixSetCookie) {
			cookieHex := label[len(prefixSetCookie):]
			if !isValidCookieHex(cookieHex) {
				continue
			}
			ensureOPT()
			opt := msg.IsEdns0()
			if opt != nil {
				opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Cookie: cookieHex})
			}
			continue
		}
		if strings.HasPrefix(label, prefixSetEDE) {
			code, textStr, ok := parseSetEDELabel(label)
			if !ok {
				continue
			}
			ensureOPT()
			opt := msg.IsEdns0()
			if opt != nil {
				opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: code, ExtraText: textStr})
			}
			continue
		}
		if strings.HasPrefix(label, prefixSetFlags) {
			rest := label[len(prefixSetFlags):]
			flags, ok := parseFlagsBitmask(rest)
			if !ok {
				continue
			}
			msg.Response = (flags>>15)&1 == 1
			msg.Opcode = int((flags >> 11) & 0xF)
			msg.Authoritative = (flags>>10)&1 == 1
			msg.Truncated = (flags>>9)&1 == 1
			msg.RecursionDesired = (flags>>8)&1 == 1
			msg.RecursionAvailable = (flags>>7)&1 == 1
			msg.Zero = (flags>>6)&1 == 1
			msg.AuthenticatedData = (flags>>5)&1 == 1
			msg.CheckingDisabled = (flags>>4)&1 == 1
			msg.Rcode = int(flags & 0xF)
			continue
		}
		if strings.HasPrefix(label, prefixSetRcode) || strings.HasPrefix(label, prefixSetStatus) {
			rest := label
			if strings.HasPrefix(label, prefixSetRcode) {
				rest = label[len(prefixSetRcode):]
			} else {
				rest = label[len(prefixSetStatus):]
			}
			if rc, ok := parseRcodeValue(rest); ok {
				msg.Rcode = rc
			}
			continue
		}
		if strings.HasPrefix(label, prefixSetID) {
			rest := label[len(prefixSetID):]
			if id, ok := parseSetIDValue(rest); ok {
				msg.Id = id
			}
			continue
		}
		if strings.HasPrefix(label, prefixSetTTL) {
			nStr := label[len(prefixSetTTL):]
			n, err := strconv.ParseUint(nStr, 10, 32)
			if err != nil || n > maxTTL {
				continue
			}
			ttl := uint32(n)
			for _, rr := range msg.Answer {
				rr.Header().Ttl = ttl
			}
			for _, rr := range msg.Ns {
				rr.Header().Ttl = ttl
			}
		}
	}
}

// parseSetEDELabel parses label "set-ede-<number>[-<text>]" and returns (code, text, true) or (0, "", false).
func parseSetEDELabel(label string) (code uint16, text string, ok bool) {
	if !strings.HasPrefix(label, prefixSetEDE) {
		return 0, "", false
	}
	rest := label[len(prefixSetEDE):]
	if rest == "" {
		return 0, "", false
	}
	idx := strings.Index(rest, "-")
	var codeStr string
	if idx < 0 {
		codeStr = rest
	} else {
		codeStr = rest[:idx]
		text = rest[idx+1:]
	}
	c, err := strconv.ParseUint(codeStr, 10, 16)
	if err != nil {
		return 0, "", false
	}
	return uint16(c), text, true
}

// parseFlagsBitmask parses binary (0/1), decimal, or 0x-prefixed hex; returns (value, true) or (0, false) if invalid or > 16 bits.
func parseFlagsBitmask(s string) (uint16, bool) {
	if s == "" {
		return 0, false
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 16)
		if err != nil || s[2:] == "" {
			return 0, false
		}
		return uint16(v), true
	}
	for _, c := range s {
		if c != '0' && c != '1' {
			v, err := strconv.ParseUint(s, 10, 16)
			if err != nil {
				return 0, false
			}
			return uint16(v), true
		}
	}
	if len(s) > 16 {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 2, 16)
	if err != nil {
		return 0, false
	}
	return uint16(v), true
}

// parseRcodeValue parses a decimal (0-15), 0x-prefixed hex, or RCODE name (e.g. NXDOMAIN, NOERROR).
// Returns (rcode, true) or (0, false). Extended RCODEs (16+) are supported; miekg/dns packs them into EDNS when present.
func parseRcodeValue(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 32)
		if err != nil || s[2:] == "" {
			return 0, false
		}
		return int(v), true
	}
	if v, err := strconv.ParseUint(s, 10, 32); err == nil {
		return int(v), true
	}
	if rc, ok := dns.StringToRcode[strings.ToUpper(s)]; ok {
		return rc, true
	}
	return 0, false
}

// isValidCookieHex returns true if s is valid hex (only 0-9a-fA-F) with even length, for EDNS0 COOKIE.
func isValidCookieHex(s string) bool {
	if s == "" || len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// parseSetIDValue parses a decimal (0-65535) or 0x-prefixed hex transaction ID.
func parseSetIDValue(s string) (uint16, bool) {
	if s == "" {
		return 0, false
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 16)
		if err != nil || s[2:] == "" {
			return 0, false
		}
		return uint16(v), true
	}
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(v), true
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

// connectionURL returns a URL-like representation of the client connection: scheme://host:port.
// Scheme is doh, dot, doq, udp, or tcp. IPv6 host is bracketed, e.g. dot://[::1]:853.
func connectionURL(transport, host, port string) string {
	scheme := strings.ToLower(transport)
	switch scheme {
	case "doh", "dot", "doq", "udp", "tcp":
		// use as-is
	default:
		scheme = "dns"
	}
	hostPart := host
	if ip := parseIP(host); ip != nil && ip.To4() == nil {
		if len(host) < 2 || host[0] != '[' || host[len(host)-1] != ']' {
			hostPart = "[" + host + "]"
		}
	}
	return scheme + "://" + hostPart + ":" + port
}

// parseEntropyRunId extracts the logical runId from a label like "runId-0" or "runId-25" (strip trailing -<digits>).
func parseEntropyRunId(leftLabel string) string {
	leftLabel = strings.TrimSpace(leftLabel)
	for i := len(leftLabel) - 1; i >= 0; i-- {
		if leftLabel[i] == '-' && i+1 < len(leftLabel) {
			suffix := leftLabel[i+1:]
			if isAllDigits(suffix) {
				return leftLabel[:i]
			}
		}
	}
	return leftLabel
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
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
	// OPT pseudo-RR: Class = UDP payload size; TTL = ext RCODE (8) | version (8) | flags (16)
	version := (opt.Hdr.Ttl >> 16) & 0xFF
	udpPayload := opt.Hdr.Class
	if udpPayload == 0 {
		udpPayload = 4096 // default if omitted
	}
	base := fmt.Sprintf("EDNS: version %d, UDP payload %d", version, udpPayload)
	if len(opt.Option) == 0 {
		return base
	}
	var parts []string
	for _, o := range opt.Option {
		parts = append(parts, o.String())
	}
	return base + "; options: " + strings.Join(parts, ", ")
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

func ednsCookieString(req *dns.Msg) string {
	opt := req.IsEdns0()
	if opt == nil {
		return "no cookie"
	}
	for _, o := range opt.Option {
		if cookie, ok := o.(*dns.EDNS0_COOKIE); ok {
			if cookie.Cookie != "" {
				return cookie.Cookie
			}
			return "no cookie"
		}
	}
	return "no cookie"
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
