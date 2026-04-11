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
// dnssecFailedSubdomain is the subdomain for DNSSEC fail-case labels: <fail-type>.dnssec-failed.<zone>
const dnssecFailedSubdomain = "dnssec-failed"

func NewSigner(zone string, ksk, zsk *KeyPair, opts ...SignerOpt) *Signer {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	zoneFQDN := dns.Fqdn(zone)
	failBase := dnssecFailedSubdomain + "." + zone
	// Keep in sync with handler: gadget labels (myip, counter, …), special hosts (www, diag, help), and dnssec-failed subdomain.
	names := []string{
		zoneFQDN,
		dns.Fqdn("addr." + zone),
		dns.Fqdn("connection." + zone),
		dns.Fqdn("diag." + zone),
		dns.Fqdn("help." + zone),
		dns.Fqdn("counter." + zone),
		dns.Fqdn("ecs." + zone),
		dns.Fqdn("edns." + zone),
		dns.Fqdn("edns-cs." + zone),
		dns.Fqdn("ip." + zone),
		dns.Fqdn("myaddr." + zone),
		dns.Fqdn("myconnection." + zone),
		dns.Fqdn("myip." + zone),
		dns.Fqdn("myport." + zone),
		dns.Fqdn("port." + zone),
		dns.Fqdn("nsec3-instead." + failBase),
		dns.Fqdn("nsec-missing." + failBase),
		dns.Fqdn("nsec-wrong-next." + failBase),
		dns.Fqdn("protocol." + zone),
		dns.Fqdn("random." + zone),
		dns.Fqdn("rrsig-expired." + failBase),
		dns.Fqdn("rrsig-future." + failBase),
		dns.Fqdn("rrsig-missing." + failBase),
		dns.Fqdn("rrsig-wrong-alg." + failBase),
		dns.Fqdn("rrsig-wrong-rrset." + failBase),
		dns.Fqdn("sig-fail." + failBase),
		dns.Fqdn("www." + zone),
		dns.Fqdn("alert.txt-test." + zone),
		dns.Fqdn("bobby-tables.txt-test." + zone),
		dns.Fqdn("href.txt-test." + zone),
		dns.Fqdn("ns1.unresolvable.ns-test." + zone),
		dns.Fqdn("ns2.unresolvable.ns-test." + zone),
		dns.Fqdn("unresolvable.ns-test." + zone),
	}
	// RFC 4034 §6.1: NSEC chain uses canonical DNS name order (compare labels from right, case-insensitive).
	sort.Slice(names, func(i, j int) bool { return dnsCanonicalLess(names[i], names[j]) })
	// Use the signer's zone as DNSKEY owner name for serving and for CDS digest (RFC 4034).
	// Keys loaded from file may have a different or missing owner; without this, CDS digest
	// would not match the zone name and parent DS validation would fail.
	ksk.DNSKEY.Hdr.Name = zoneFQDN
	zsk.DNSKEY.Hdr.Name = zoneFQDN
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

// ExistingNames returns a copy of the signer's NSEC name list (for tests and drift detection).
func (s *Signer) ExistingNames() []string {
	out := make([]string, len(s.existingNames))
	copy(out, s.existingNames)
	return out
}

// isDNSSECRequestType returns true if qtype is a DNSSEC record type (RRSIG, NSEC, NSEC3, DNSKEY, DS).
// Include DNSSEC data when the client asks for one of these types or when the EDNS DO bit is set.
func isDNSSECRequestType(qtype uint16) bool {
	switch qtype {
	case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeDNSKEY, dns.TypeDS:
		return true
	default:
		return false
	}
}

// SignResponse signs the message: adds RRSIGs to Answer and Ns, adds NSEC for NXDOMAIN/no-data.
// DNSSEC data (RRSIG, NSEC, DNSKEY in Ns) is only included when:
// 1) the requested qtype is a DNSSEC type (RRSIG, NSEC, NSEC3, DNSKEY, DS), or
// 2) the request has EDNS with the DO (DNSSEC OK) bit set (e.g. dig +dnssec).
// If req is nil, qname/qtype are taken from msg.Question and DO is treated as set (e.g. for tests).
func (s *Signer) SignResponse(msg *dns.Msg, req *dns.Msg) error {
	var qname string
	var qtype uint16
	doBit := true
	if req != nil && len(req.Question) > 0 {
		qname = req.Question[0].Name
		qtype = req.Question[0].Qtype
		doBit = false
		if opt := req.IsEdns0(); opt != nil {
			doBit = opt.Do()
		}
	} else if msg != nil && len(msg.Question) > 0 {
		qname = msg.Question[0].Name
		qtype = msg.Question[0].Qtype
	} else {
		return nil
	}
	wantDNSSEC := doBit || isDNSSECRequestType(qtype)
	if !wantDNSSEC {
		qnameFQDN := dns.Fqdn(strings.ToLower(qname))
		if s.zoneFQDN == qnameFQDN && qtype == dns.TypeDNSKEY {
			msg.Answer = append(msg.Answer, s.ksk.DNSKEY, s.zsk.DNSKEY)
		}
		return nil
	}

	now := time.Now().UTC()
	inception := now.Add(-s.inceptionOffset).Unix()
	expiration := now.Add(s.validityDuration).Unix()
	// For rrsig-expired / rrsig-future fail-case labels
	expiredInception := now.Add(-48 * time.Hour).Unix()
	expiredExpiration := now.Add(-24 * time.Hour).Unix()
	futureInception := now.Add(365 * 24 * time.Hour).Unix()             // 1 year from now
	futureExpiration := now.Add(365*24*time.Hour + 24*time.Hour).Unix() // 1 year + 24h

	qnameFQDN := dns.Fqdn(strings.ToLower(qname))

	// Add DNSKEY at apex: Answer for DNSKEY query (RFC 4034), Ns for no-data (SOA) response
	if s.zoneFQDN == qnameFQDN {
		if qtype == dns.TypeDNSKEY {
			msg.Answer = append(msg.Answer, s.ksk.DNSKEY, s.zsk.DNSKEY)
		} else if len(msg.Ns) > 0 && msg.Ns[0].Header().Rrtype == dns.TypeSOA {
			msg.Ns = append(msg.Ns, s.ksk.DNSKEY, s.zsk.DNSKEY)
		}
	}

	// Sign Answer section
	msg.Answer = s.signSection(msg.Answer, inception, expiration, expiredInception, expiredExpiration, futureInception, futureExpiration, false)

	// Sign Ns section (use KSK for DNSKEY RRset, ZSK for others)
	msg.Ns = s.signSection(msg.Ns, inception, expiration, expiredInception, expiredExpiration, futureInception, futureExpiration, true)

	// For NXDOMAIN or no-data (SOA in Ns), add NSEC (or NSEC3 / skip) covering the gap
	isNoData := msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0 && len(msg.Ns) > 0 && msg.Ns[0].Header().Rrtype == dns.TypeSOA
	nsecMissingFQDN := s.dnssecFailedFQDN("nsec-missing")
	nsec3InsteadFQDN := s.dnssecFailedFQDN("nsec3-instead")
	if msg.Rcode == dns.RcodeNameError || isNoData {
		if qnameFQDN == nsecMissingFQDN {
			// Skip NSEC entirely so validators see denial without NSEC
		} else if qnameFQDN == nsec3InsteadFQDN {
			// Emit NSEC3 instead of NSEC (zone is NSEC-only; validators expect NSEC)
			nsec3 := s.nsec3ForName(qnameFQDN, qtype, isNoData)
			msg.Ns = append(msg.Ns, nsec3...)
		} else {
			nsecs := s.nsecForName(qnameFQDN, qtype, isNoData)
			msg.Ns = append(msg.Ns, nsecs...)
			// RFC 4035 §3.1.3.2: for NXDOMAIN also include an NSEC that covers the wildcard (*.<zone>)
			if msg.Rcode == dns.RcodeNameError {
				if wc := s.nsecForWildcard(); wc != nil {
					msg.Ns = append(msg.Ns, wc)
				}
			}
			// Sign each NSEC RRset separately (RFC 4035: RRset = same owner + type)
			var nsecRRs []dns.RR
			for _, rr := range msg.Ns {
				if rr.Header().Rrtype == dns.TypeNSEC {
					nsecRRs = append(nsecRRs, rr)
				}
			}
			for _, rrset := range groupRRSet(nsecRRs) {
				if len(rrset) == 0 {
					continue
				}
				sigs, err := s.signRRSetWithKey(rrset, s.zsk, inception, expiration)
				if err != nil {
					return err
				}
				msg.Ns = append(msg.Ns, sigs...)
			}
		}
	}

	return nil
}

// fqdnForCompare returns a canonical FQDN for case-insensitive name matching (resolver 0x20 qname case).
func fqdnForCompare(name string) string {
	return dns.Fqdn(strings.ToLower(strings.TrimSuffix(name, ".")))
}

// signSection groups RRs by (name, type), signs each RRset, returns new slice with RRs + RRSIGs.
// expired* and future* are used for rrsig-expired / rrsig-future fail-case labels.
func (s *Signer) signSection(rrs []dns.RR, inception, expiration, expiredInception, expiredExpiration, futureInception, futureExpiration int64, nsSection bool) []dns.RR {
	groups := groupRRSet(rrs)
	rrsigExpiredFQDN := s.dnssecFailedFQDN("rrsig-expired")
	rrsigFutureFQDN := s.dnssecFailedFQDN("rrsig-future")
	rrsigMissingFQDN := s.dnssecFailedFQDN("rrsig-missing")
	var out []dns.RR
	for _, rrset := range groups {
		out = append(out, rrset...)
		owner := ""
		if len(rrset) > 0 {
			owner = rrset[0].Header().Name
		}
		inc, exp := inception, expiration
		ownerCmp := fqdnForCompare(owner)
		if ownerCmp == rrsigExpiredFQDN {
			inc, exp = expiredInception, expiredExpiration
		} else if ownerCmp == rrsigFutureFQDN {
			inc, exp = futureInception, futureExpiration
		}
		if ownerCmp == rrsigMissingFQDN {
			// Do not append any RRSIG for this RRset
			continue
		}
		// DNSKEY RRset: sign with both KSK and ZSK (KSK first so DS→KSK→DNSKEY chain is clear for DNSViz/tools)
		if len(rrset) > 0 && rrset[0].Header().Rrtype == dns.TypeDNSKEY {
			sigK, _ := s.signRRSetWithKey(rrset, s.ksk, inc, exp)
			sigZ, _ := s.signRRSetWithKey(rrset, s.zsk, inc, exp)
			out = append(out, sigK...)
			out = append(out, sigZ...)
		} else if len(rrset) > 0 && rrset[0].Header().Rrtype == dns.TypeCDS {
			// CDS RRset must be signed by a key in both DNSKEY and DS (RFC 7344 §4.1) — i.e. the KSK
			sigs, _ := s.signRRSetWithKey(rrset, s.ksk, inc, exp)
			out = append(out, sigs...)
		} else {
			sigs, _ := s.signRRSetWithKey(rrset, s.zsk, inc, exp)
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
	// rrsig-wrong-rrset.<zone>: sign a different RRset so digest verification fails
	rrsigWrongRRsetFQDN := s.dnssecFailedFQDN("rrsig-wrong-rrset")
	if fqdnForCompare(h.Name) == rrsigWrongRRsetFQDN {
		wrongRRset := []dns.RR{&dns.SOA{
			Hdr:     dns.RR_Header{Name: s.zoneFQDN, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:      ".",
			Mbox:    ".",
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  300,
		}}
		_ = rrsig.Sign(kp.PrivateKey, wrongRRset)
	} else if err := rrsig.Sign(kp.PrivateKey, rrset); err != nil {
		return nil, err
	}
	// sig-fail.dnssec-failed.<zone>: deliberately invalid RRSIG for the gadget RRset (A/TXT) so validators get SERVFAIL.
	// Do not corrupt RRSIGs for NSEC at sig-fail (used in NXDOMAIN when qname sorts after sig-fail), or Pack() fails.
	sigFailFQDN := s.dnssecFailedFQDN("sig-fail")
	if fqdnForCompare(h.Name) == sigFailFQDN && h.Rrtype != dns.TypeNSEC {
		// Corrupt the signature so validation fails.
		sig := []byte(rrsig.Signature)
		for i := range sig {
			sig[i] ^= 0xff
		}
		rrsig.Signature = string(sig)
	}
	// rrsig-wrong-alg.dnssec-failed.<zone>: RRSIG claims wrong algorithm so validators fail to match DNSKEY
	rrsigWrongAlgFQDN := s.dnssecFailedFQDN("rrsig-wrong-alg")
	if fqdnForCompare(h.Name) == rrsigWrongAlgFQDN {
		// Use a different algorithm number (e.g. 8 RSASHA256 if zone is 13/15)
		if kp.DNSKEY.Algorithm == dns.ECDSAP256SHA256 || kp.DNSKEY.Algorithm == dns.ED25519 {
			rrsig.Algorithm = dns.RSASHA256
		} else {
			rrsig.Algorithm = dns.ECDSAP256SHA256
		}
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
		key := fqdnForCompare(rr.Header().Name) + " " + dns.TypeToString[rr.Header().Rrtype]
		if i, ok := seen[key]; ok {
			groups[i] = append(groups[i], rr)
		} else {
			seen[key] = len(groups)
			groups = append(groups, []dns.RR{rr})
		}
	}
	return groups
}

func (s *Signer) nsecForName(name string, qtype uint16, isNoData bool) []dns.RR {
	name = dns.Fqdn(strings.ToLower(name))
	prev, next := s.prevNext(name)
	// Name exists: NODATA needs NSEC(owner=name, NextDomain=next, TypeBitMap=types at name \ {qtype}).
	// For NODATA we must use this path even when name is not in existingNames (e.g. delay-10, ttl-N, size-N).
	if prev == "" && next == "" || isNoData {
		var nextName string
		if prev == "" && next == "" {
			nextName = s.nextForExistingName(name)
		} else {
			nextName = s.nextNameInZoneAfter(name)
		}
		// nsec-wrong-next.dnssec-failed.<zone>: last name in zone must have NextDomain = apex; we set wrong value so validators get bogus.
		nsecWrongNextFQDN := s.dnssecFailedFQDN("nsec-wrong-next")
		if name == nsecWrongNextFQDN && nextName == s.zoneFQDN {
			for _, n := range s.existingNames {
				if n != s.zoneFQDN {
					nextName = n
					break
				}
			}
		}
		if nextName == "" {
			return nil
		}
		types := s.typesAtName(name)
		bitmap := make([]uint16, 0, len(types))
		for _, t := range types {
			if t != qtype {
				bitmap = append(bitmap, t)
			}
		}
		if len(bitmap) == 0 {
			return nil
		}
		sort.Slice(bitmap, func(i, j int) bool { return bitmap[i] < bitmap[j] })
		nsec := &dns.NSEC{
			Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
			NextDomain: nextName,
			TypeBitMap: bitmap,
		}
		return []dns.RR{nsec}
	}
	// NXDOMAIN: qname sorts before first existing name. RFC 4034 §4.1.1: the last NSEC in the zone
	// must have NextDomain = zone apex. existingNames is in canonical order so [0]=apex, [len-1]=last.
	if prev == "" {
		if len(s.existingNames) == 0 {
			return nil
		}
		last := s.existingNames[len(s.existingNames)-1]
		firstAfterApex := s.zoneFQDN
		if len(s.existingNames) > 1 {
			firstAfterApex = s.existingNames[1]
		}
		typesLast := s.typesAtName(last)
		sort.Slice(typesLast, func(i, j int) bool { return typesLast[i] < typesLast[j] })
		typesApex := s.typesAtName(s.zoneFQDN)
		return []dns.RR{
			&dns.NSEC{
				Hdr:        dns.RR_Header{Name: last, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: s.zoneFQDN,
				TypeBitMap: typesLast,
			},
			&dns.NSEC{
				Hdr:        dns.RR_Header{Name: s.zoneFQDN, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: firstAfterApex,
				TypeBitMap: typesApex,
			},
		}
	}
	typesPrev := s.typesAtName(prev)
	sort.Slice(typesPrev, func(i, j int) bool { return typesPrev[i] < typesPrev[j] })
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: prev, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: next,
		TypeBitMap: typesPrev,
	}
	return []dns.RR{nsec}
}

// nsecForWildcard returns an NSEC RR that covers the wildcard (*.<zone>) for NXDOMAIN proof of non-existence.
// RFC 4035 §3.1.3.2: the name server MUST include an NSEC RR proving that no RRsets match via wildcard expansion.
// Uses a synthetic owner "!.<zone>" (sorts before "*.<zone>") and next = first existing name >= wildcard.
func (s *Signer) nsecForWildcard() dns.RR {
	wildcardFQDN := dns.Fqdn("*." + s.zone)
	if len(s.existingNames) == 0 {
		return nil
	}
	i := s.canonicalSearch(wildcardFQDN)
	var nextName string
	if i < len(s.existingNames) {
		nextName = s.existingNames[i]
	} else {
		nextName = s.existingNames[0]
	}
	// Synthetic owner that sorts before *.zone (e.g. "!.example.com."; '!' < '*')
	ownerFQDN := dns.Fqdn("!." + s.zone)
	bitmap := []uint16{dns.TypeNSEC, dns.TypeRRSIG}
	sort.Slice(bitmap, func(a, b int) bool { return bitmap[a] < bitmap[b] })
	return &dns.NSEC{
		Hdr:        dns.RR_Header{Name: ownerFQDN, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: nextName,
		TypeBitMap: bitmap,
	}
}

// nsec3ForName returns one or more NSEC3 RRs for the nsec3-instead fail case (zone is NSEC-only; returning NSEC3 is bogus).
func (s *Signer) nsec3ForName(name string, qtype uint16, isNoData bool) []dns.RR {
	// Minimal NSEC3: placeholder owner and next hashed owner (base32). Validators expect NSEC for this zone.
	ownerNSEC3 := "0." + s.zoneFQDN // placeholder hashed-owner label
	nsec3 := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: ownerNSEC3, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash:       1, // SHA-1
		Flags:      0,
		Iterations: 0,
		SaltLength: 0,
		Salt:       "",
		HashLength: 1,
		NextDomain: "0",
		TypeBitMap: []uint16{dns.TypeSOA},
	}
	return []dns.RR{nsec3}
}

// nextForExistingName returns the next name in canonical order after name (name must be in existingNames).
func (s *Signer) nextForExistingName(name string) string {
	i := s.canonicalSearch(name)
	if i >= len(s.existingNames) || s.existingNames[i] != name {
		return ""
	}
	nextIdx := (i + 1) % len(s.existingNames)
	return s.existingNames[nextIdx]
}

// nextNameInZoneAfter returns the next existing name in zone (canonical) order after name (name need not be in existingNames).
// Used for NODATA NSEC when the name is a dynamic gadget (e.g. delay-10, ttl-N) not in existingNames.
func (s *Signer) nextNameInZoneAfter(name string) string {
	if len(s.existingNames) == 0 {
		return ""
	}
	i := s.canonicalSearch(name)
	// existingNames[i] is the first >= name in canonical order. Skip if equal to get next after name.
	for i < len(s.existingNames) && s.existingNames[i] == name {
		i++
	}
	if i < len(s.existingNames) {
		return s.existingNames[i]
	}
	// name sorts after all existing names; next is apex (wrap)
	return s.existingNames[0]
}

// typesAtName returns the RR types served at this name (for NSEC TypeBitMap in NODATA).
func (s *Signer) typesAtName(name string) []uint16 {
	if name == s.zoneFQDN {
		// Apex: we serve SOA, NS, A, AAAA, DNSKEY, CDS (and RRSIG/NSEC for DNSSEC); sorted by type code
		t := []uint16{dns.TypeA, dns.TypeNS, dns.TypeSOA, dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY, dns.TypeCDS}
		sort.Slice(t, func(i, j int) bool { return t[i] < t[j] })
		return t
	}
	nameTrim := strings.TrimSuffix(strings.ToLower(name), ".")
	if !strings.HasSuffix(nameTrim, "."+s.zone) {
		return []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT}
	}
	label := strings.SplitN(nameTrim, ".", 2)[0]
	// Dynamic gadget names (only TXT): delay-N, ttl-N, timestamp-N, size-N.
	if strings.HasPrefix(label, "delay-") || strings.HasPrefix(label, "ttl-") || strings.HasPrefix(label, "timestamp-") || strings.HasPrefix(label, "size-") {
		return []uint16{dns.TypeTXT}
	}
	failBase := dnssecFailedSubdomain + "." + s.zone
	switch nameTrim {
	case "ip." + s.zone, "myip." + s.zone, "addr." + s.zone, "myaddr." + s.zone:
		return []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT}
	case "port." + s.zone, "myport." + s.zone, "connection." + s.zone, "myconnection." + s.zone,
		"protocol." + s.zone, "counter." + s.zone,
		"ecs." + s.zone, "edns." + s.zone, "edns-cs." + s.zone,
		"random." + s.zone,
		"sig-fail." + failBase, "rrsig-expired." + failBase, "rrsig-future." + failBase,
		"rrsig-wrong-alg." + failBase, "rrsig-wrong-rrset." + failBase, "rrsig-missing." + failBase:
		return []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT}
	case "nsec-missing." + failBase, "nsec-wrong-next." + failBase, "nsec3-instead." + failBase:
		return []uint16{dns.TypeTXT}
	default:
		// Other subdomains (e.g. qname-min, diag, www, ns0): allow A, AAAA, TXT
		return []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT}
	}
}

func (s *Signer) prevNext(name string) (prev, next string) {
	i := s.canonicalSearch(name)
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

// dnssecFailedFQDN returns the FQDN for a fail-type under dnssec-failed.<zone>.
func (s *Signer) dnssecFailedFQDN(failType string) string {
	return dns.Fqdn(failType + "." + dnssecFailedSubdomain + "." + s.zone)
}

// CDSRecord returns the CDS record for the KSK (for parent DS).
func (s *Signer) CDSRecord() *dns.CDS {
	ds := s.ksk.DNSKEY.ToDS(dns.SHA256)
	if ds == nil {
		return nil
	}
	return ds.ToCDS()
}

// dnsCanonicalLess returns true if a sorts before b in canonical DNS name order (RFC 4034 §6.1).
// Names are compared label-by-label from the right (least significant first), case-insensitive;
// the shorter name is treated as if padded with empty labels on the left (empty is smallest).
func dnsCanonicalLess(a, b string) bool {
	la := dns.SplitDomainName(a)
	lb := dns.SplitDomainName(b)
	maxK := len(la)
	if len(lb) > maxK {
		maxK = len(lb)
	}
	for k := 0; k < maxK; k++ {
		var aLabel, bLabel string
		if k < len(la) {
			aLabel = la[len(la)-1-k]
		}
		if k < len(lb) {
			bLabel = lb[len(lb)-1-k]
		}
		aLower := strings.ToLower(aLabel)
		bLower := strings.ToLower(bLabel)
		if aLower < bLower {
			return true
		}
		if aLower > bLower {
			return false
		}
	}
	return false
}

// canonicalSearch returns the smallest index i such that existingNames[i] >= name in canonical order.
// If name is greater than all, returns len(existingNames).
func (s *Signer) canonicalSearch(name string) int {
	return sort.Search(len(s.existingNames), func(i int) bool {
		return !dnsCanonicalLess(s.existingNames[i], name)
	})
}
