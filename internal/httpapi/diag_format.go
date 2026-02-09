package httpapi

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// FormatDNSMsg unpacks wire bytes and returns a tshark-style decode, or an error line and hex dump on unpack failure.
func FormatDNSMsg(wire []byte) string {
	if len(wire) == 0 {
		return "(empty)"
	}
	var msg dns.Msg
	if err := msg.Unpack(wire); err != nil {
		return fmt.Sprintf("(unpack error: %v)\n\nRaw (hex):\n%s", err, HexDump(wire))
	}
	return formatMsg(&msg)
}

func formatMsg(m *dns.Msg) string {
	var b strings.Builder
	kind := "query"
	if m.Response {
		kind = "response"
	}
	fmt.Fprintf(&b, "Domain Name System (%s)\n", kind)
	fmt.Fprintf(&b, "    Transaction ID: 0x%04x\n", m.Id)
	flagsVal := uint16(m.Rcode&0xF) | uint16(m.Opcode&0xF)<<11
	if m.Response {
		flagsVal |= 1 << 15
	}
	if m.Authoritative {
		flagsVal |= 1 << 10
	}
	if m.Truncated {
		flagsVal |= 1 << 9
	}
	if m.RecursionDesired {
		flagsVal |= 1 << 8
	}
	if m.RecursionAvailable {
		flagsVal |= 1 << 7
	}
	flags := "0x" + strconv.FormatUint(uint64(flagsVal), 16)
	if m.Response {
		flags += " Response"
	} else {
		flags += " Standard query"
	}
	if m.Authoritative {
		flags += ", Authoritative"
	}
	if m.Truncated {
		flags += ", Truncated"
	}
	if m.RecursionDesired {
		flags += ", Recursion desired"
	}
	if m.RecursionAvailable {
		flags += ", Recursion available"
	}
	if m.Rcode != dns.RcodeSuccess {
		flags += ", " + dns.RcodeToString[m.Rcode]
	}
	fmt.Fprintf(&b, "    Flags: %s\n", flags)
	fmt.Fprintf(&b, "    Questions: %d\n", len(m.Question))
	fmt.Fprintf(&b, "    Answer RRs: %d\n", len(m.Answer))
	fmt.Fprintf(&b, "    Authority RRs: %d\n", len(m.Ns))
	fmt.Fprintf(&b, "    Additional RRs: %d\n", len(m.Extra))

	if len(m.Question) > 0 {
		b.WriteString("    Queries\n")
		for _, q := range m.Question {
			typeStr := dns.TypeToString[q.Qtype]
			if typeStr == "" {
				typeStr = fmt.Sprintf("TYPE%d", q.Qtype)
			}
			classStr := classString(q.Qclass)
			fmt.Fprintf(&b, "        %s: type %s, class %s\n", q.Name, typeStr, classStr)
		}
	}
	if len(m.Answer) > 0 {
		b.WriteString("    Answers\n")
		for _, rr := range m.Answer {
			formatRR(&b, rr, "        ")
		}
	}
	if len(m.Ns) > 0 {
		b.WriteString("    Authoritative nameservers\n")
		for _, rr := range m.Ns {
			formatRR(&b, rr, "        ")
		}
	}
	if len(m.Extra) > 0 {
		b.WriteString("    Additional records\n")
		for _, rr := range m.Extra {
			formatRR(&b, rr, "        ")
		}
	}
	return b.String()
}

func classString(class uint16) string {
	switch class {
	case dns.ClassINET:
		return "IN"
	case dns.ClassCHAOS:
		return "CH"
	default:
		return fmt.Sprintf("CLASS%d", class)
	}
}

func formatRR(b *strings.Builder, rr dns.RR, indent string) {
	h := rr.Header()
	if h.Rrtype == dns.TypeOPT {
		fmt.Fprintf(b, "%s%s: type OPT (EDNS)\n", indent, h.Name)
	} else {
		typeStr := dns.TypeToString[h.Rrtype]
		if typeStr == "" {
			typeStr = fmt.Sprintf("TYPE%d", h.Rrtype)
		}
		classStr := classString(h.Class)
		fmt.Fprintf(b, "%s%s: type %s, class %s, TTL %d\n", indent, h.Name, typeStr, classStr, h.Ttl)
	}
	switch v := rr.(type) {
	case *dns.A:
		fmt.Fprintf(b, "%s    Address: %s\n", indent, v.A.String())
	case *dns.AAAA:
		fmt.Fprintf(b, "%s    Address: %s\n", indent, v.AAAA.String())
	case *dns.TXT:
		for _, s := range v.Txt {
			fmt.Fprintf(b, "%s    \"%s\"\n", indent, s)
		}
	case *dns.NS:
		fmt.Fprintf(b, "%s    NS: %s\n", indent, v.Ns)
	case *dns.CNAME:
		fmt.Fprintf(b, "%s    CNAME: %s\n", indent, v.Target)
	case *dns.MX:
		fmt.Fprintf(b, "%s    Mailbox: %s, preference: %d\n", indent, v.Mx, v.Preference)
	case *dns.SOA:
		fmt.Fprintf(b, "%s    Mname: %s, Rname: %s, Serial: %d, Refresh: %d, Retry: %d, Expire: %d, Minttl: %d\n",
			indent, v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *dns.RRSIG:
		typeCovered := dns.TypeToString[v.TypeCovered]
		if typeCovered == "" {
			typeCovered = fmt.Sprintf("TYPE%d", v.TypeCovered)
		}
		algStr := dns.AlgorithmToString[v.Algorithm]
		if algStr == "" {
			algStr = fmt.Sprintf("%d", v.Algorithm)
		} else {
			algStr = fmt.Sprintf("%d (%s)", v.Algorithm, algStr)
		}
		fmt.Fprintf(b, "%s    Type Covered: %s\n", indent, typeCovered)
		fmt.Fprintf(b, "%s    Algorithm: %s\n", indent, algStr)
		fmt.Fprintf(b, "%s    Labels: %d\n", indent, v.Labels)
		fmt.Fprintf(b, "%s    Original TTL: %d\n", indent, v.OrigTtl)
		fmt.Fprintf(b, "%s    Signature Expiration: %s\n", indent, dns.TimeToString(v.Expiration))
		fmt.Fprintf(b, "%s    Signature Inception: %s\n", indent, dns.TimeToString(v.Inception))
		fmt.Fprintf(b, "%s    Key Tag: %d\n", indent, v.KeyTag)
		fmt.Fprintf(b, "%s    Signer's Name: %s\n", indent, v.SignerName)
		fmt.Fprintf(b, "%s    Signature: <%d bytes base64>\n", indent, len(v.Signature))
	case *dns.PTR:
		fmt.Fprintf(b, "%s    PTR: %s\n", indent, v.Ptr)
	case *dns.SRV:
		fmt.Fprintf(b, "%s    Target: %s, port: %d, priority: %d, weight: %d\n", indent, v.Target, v.Port, v.Priority, v.Weight)
	case *dns.CAA:
		fmt.Fprintf(b, "%s    Tag: %s, Value: %s\n", indent, v.Tag, v.Value)
	case *dns.OPT:
		// OPT pseudo-RR: Class = UDP payload size; TTL = ext RCODE (8) | version (8) | flags (16)
		version := (v.Hdr.Ttl >> 16) & 0xFF
		extRcode := (v.Hdr.Ttl >> 24) & 0xFF
		flags := v.Hdr.Ttl & 0xFFFF
		fmt.Fprintf(b, "%s    EDNS: version %d, flags 0x%04x, UDP payload %d\n", indent, version, flags, v.Hdr.Class)
		if extRcode != 0 {
			fmt.Fprintf(b, "%s    Extended RCODE: %d\n", indent, extRcode)
		}
		for _, o := range v.Option {
			fmt.Fprintf(b, "%s    Option: %s\n", indent, o.String())
		}
	default:
		// Generic rdata: use String() which gives type-specific format
		s := rr.String()
		if idx := strings.Index(s, "\t"); idx >= 0 {
			s = s[idx+1:]
		}
		// Split long lines
		for _, line := range strings.Split(s, " ") {
			if line != "" {
				fmt.Fprintf(b, "%s    %s\n", indent, line)
			}
		}
	}
}

// RawHex returns the wire bytes as a single line of hex characters (no spaces or newlines).
func RawHex(wire []byte) string {
	return hex.EncodeToString(wire)
}

// HexDump returns a byte-for-byte hex dump (16 bytes per line, offset + hex + ASCII).
func HexDump(wire []byte) string {
	if len(wire) == 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(wire); i += 16 {
		fmt.Fprintf(&b, "%04x  ", i)
		end := i + 16
		if end > len(wire) {
			end = len(wire)
		}
		for j := i; j < end; j++ {
			fmt.Fprintf(&b, "%02x ", wire[j])
		}
		for j := end - i; j < 16; j++ {
			b.WriteString("   ")
		}
		b.WriteString(" ")
		for j := i; j < end; j++ {
			c := wire[j]
			if c >= 32 && c < 127 {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// FormatDNSMsgHTML returns HTML-escaped tshark-style decode; safe for embedding in HTML.
func FormatDNSMsgHTML(wire []byte) string {
	s := FormatDNSMsg(wire)
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
