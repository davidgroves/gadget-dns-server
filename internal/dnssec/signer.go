package dnssec

import (
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Signer signs DNS responses with RRSIGs and adds NSEC for denial.
type Signer struct {
	zone             string
	zoneFQDN         string
	ksk              *KeyPair
	zsk              *KeyPair
	existingNames    []string
	inceptionOffset  time.Duration // RRSIG inception = now - inceptionOffset
	validityDuration time.Duration // RRSIG expiration = now + validityDuration
}

// SignerOpt is an option for NewSigner.
type SignerOpt func(*Signer)

// WithRRSIGValidity sets RRSIG inception offset and validity duration (e.g. 1*time.Hour, 24*time.Hour).
func WithRRSIGValidity(inceptionOffset, validityDuration time.Duration) SignerOpt {
	return func(s *Signer) {
		s.inceptionOffset = inceptionOffset
		s.validityDuration = validityDuration
	}
}

// NewSigner creates a signer for the zone with the given KSK and ZSK.
// Default RRSIG validity: inception 1h before now, expiration 24h after now.
// Use WithRRSIGValidity to override.
func NewSigner(zone string, ksk, zsk *KeyPair, opts ...SignerOpt) *Signer {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	zoneFQDN := dns.Fqdn(zone)
	names := []string{
		zoneFQDN,
		dns.Fqdn("counter." + zone),
		dns.Fqdn("ecs." + zone),
		dns.Fqdn("edns." + zone),
		dns.Fqdn("edns-cs." + zone),
		dns.Fqdn("myaddr." + zone),
		dns.Fqdn("myip." + zone),
		dns.Fqdn("myport." + zone),
		dns.Fqdn("protocol." + zone),
		dns.Fqdn("random." + zone),
		dns.Fqdn("sig-fail." + zone),
		dns.Fqdn("timestamp." + zone),
		dns.Fqdn("timestamp0." + zone),
	}
	sort.Strings(names)
	s := &Signer{
		zone:             zone,
		zoneFQDN:         zoneFQDN,
		ksk:              ksk,
		zsk:              zsk,
		existingNames:    names,
		inceptionOffset:  time.Hour,
		validityDuration: 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// SignResponse signs the message: adds RRSIGs to Answer and Ns, adds NSEC for NXDOMAIN/no-data.
func (s *Signer) SignResponse(msg *dns.Msg, qname string, qtype uint16) error {
	now := time.Now().UTC()
	inception := now.Add(-s.inceptionOffset).Unix()
	expiration := now.Add(s.validityDuration).Unix()

	qnameFQDN := dns.Fqdn(strings.ToLower(qname))

	// Add DNSKEY at apex when query is for DNSKEY or we're returning SOA (no-data)
	if s.zoneFQDN == qnameFQDN {
		if qtype == dns.TypeDNSKEY || (len(msg.Ns) > 0 && msg.Ns[0].Header().Rrtype == dns.TypeSOA) {
			msg.Ns = append(msg.Ns, s.ksk.DNSKEY, s.zsk.DNSKEY)
		}
	}

	// Sign Answer section
	msg.Answer = s.signSection(msg.Answer, inception, expiration, false)

	// Sign Ns section (use KSK for DNSKEY RRset, ZSK for others)
	msg.Ns = s.signSection(msg.Ns, inception, expiration, true)

	// For NXDOMAIN or no-data (SOA in Ns), add NSEC covering the gap
	if msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0 && len(msg.Ns) > 0 && msg.Ns[0].Header().Rrtype == dns.TypeSOA) {
		nsecs := s.nsecForName(qnameFQDN)
		msg.Ns = append(msg.Ns, nsecs...)
		// Sign the NSEC RRset(s)
		var nsecRRs []dns.RR
		for _, rr := range msg.Ns {
			if rr.Header().Rrtype == dns.TypeNSEC {
				nsecRRs = append(nsecRRs, rr)
			}
		}
		if len(nsecRRs) > 0 {
			sigs, err := s.signRRSetWithKey(nsecRRs, s.zsk, inception, expiration)
			if err != nil {
				return err
			}
			msg.Ns = append(msg.Ns, sigs...)
		}
	}

	return nil
}

// signSection groups RRs by (name, type), signs each RRset, returns new slice with RRs + RRSIGs.
func (s *Signer) signSection(rrs []dns.RR, inception, expiration int64, nsSection bool) []dns.RR {
	groups := groupRRSet(rrs)
	var out []dns.RR
	for _, rrset := range groups {
		out = append(out, rrset...)
		// DNSKEY RRset: sign with both ZSK and KSK
		if nsSection && len(rrset) > 0 && rrset[0].Header().Rrtype == dns.TypeDNSKEY {
			sigZ, _ := s.signRRSetWithKey(rrset, s.zsk, inception, expiration)
			sigK, _ := s.signRRSetWithKey(rrset, s.ksk, inception, expiration)
			out = append(out, sigZ...)
			out = append(out, sigK...)
		} else {
			sigs, _ := s.signRRSetWithKey(rrset, s.zsk, inception, expiration)
			out = append(out, sigs...)
		}
	}
	return out
}

func (s *Signer) signRRSetWithKey(rrset []dns.RR, kp *KeyPair, inception, expiration int64) ([]dns.RR, error) {
	if len(rrset) == 0 {
		return nil, nil
	}
	h := rrset[0].Header()
	rrsig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: h.Name, Rrtype: dns.TypeRRSIG, Class: h.Class, Ttl: h.Ttl},
		TypeCovered: h.Rrtype,
		Algorithm:   kp.DNSKEY.Algorithm,
		Labels:      uint8(dns.CountLabel(h.Name)),
		OrigTtl:     h.Ttl,
		Expiration:  uint32(expiration),
		Inception:   uint32(inception),
		KeyTag:      kp.DNSKEY.KeyTag(),
		SignerName:  s.zoneFQDN,
	}
	if err := rrsig.Sign(kp.PrivateKey, rrset); err != nil {
		return nil, err
	}
	// sig-fail.<zone>: deliberately invalid RRSIG so validators get SERVFAIL.
	sigFailFQDN := dns.Fqdn("sig-fail." + s.zone)
	if h.Name == sigFailFQDN {
		// Corrupt the signature so validation fails.
		sig := []byte(rrsig.Signature)
		for i := range sig {
			sig[i] ^= 0xff
		}
		rrsig.Signature = string(sig)
	}
	return []dns.RR{rrsig}, nil
}

func groupRRSet(rrs []dns.RR) [][]dns.RR {
	var groups [][]dns.RR
	seen := make(map[string]int)
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		key := rr.Header().Name + " " + dns.TypeToString[rr.Header().Rrtype]
		if i, ok := seen[key]; ok {
			groups[i] = append(groups[i], rr)
		} else {
			seen[key] = len(groups)
			groups = append(groups, []dns.RR{rr})
		}
	}
	return groups
}

func (s *Signer) nsecForName(name string) []dns.RR {
	name = dns.Fqdn(strings.ToLower(name))
	prev, next := s.prevNext(name)
	if prev == "" && next == "" {
		return nil
	}
	if prev == "" {
		return nil
	}
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: prev, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: next,
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY},
	}
	return []dns.RR{nsec}
}

func (s *Signer) prevNext(name string) (prev, next string) {
	i := sort.SearchStrings(s.existingNames, name)
	if i < len(s.existingNames) && s.existingNames[i] == name {
		return "", ""
	}
	if i == 0 {
		prev = ""
		next = s.existingNames[0]
	} else if i == len(s.existingNames) {
		prev = s.existingNames[i-1]
		next = s.zoneFQDN
	} else {
		prev = s.existingNames[i-1]
		next = s.existingNames[i]
	}
	return prev, next
}

// CDSRecord returns the CDS record for the KSK (for parent DS).
func (s *Signer) CDSRecord() *dns.CDS {
	ds := s.ksk.DNSKEY.ToDS(dns.SHA256)
	if ds == nil {
		return nil
	}
	return ds.ToCDS()
}
