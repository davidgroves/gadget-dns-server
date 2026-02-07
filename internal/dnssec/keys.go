package dnssec

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
)

// Algorithm constants (DNSSEC algorithm numbers).
const (
	ALG_RSASHA256       = 8  // RFC 5702
	ALG_ECDSAP256SHA256 = 13 // RFC 6605
	ALG_ED25519         = 15 // RFC 8080
)

// KeyPair holds a private key and its DNSKEY for signing.
type KeyPair struct {
	PrivateKey crypto.Signer
	DNSKEY     *dns.DNSKEY
}

// GenerateKeyPair generates a KSK or ZSK in the given algorithm.
// alg: ALG_RSASHA256 (8), ALG_ECDSAP256SHA256 (13), or ALG_ED25519 (15).
// ksk: true for KSK (SEP bit set), false for ZSK.
func GenerateKeyPair(zone string, alg uint8, ksk bool) (*KeyPair, error) {
	zone = dns.Fqdn(zone)
	flags := uint16(dns.ZONE)
	if ksk {
		flags |= dns.SEP
	}
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: alg,
	}
	bits := keyBits(alg)
	priv, err := key.Generate(bits)
	if err != nil {
		return nil, err
	}
	return &KeyPair{PrivateKey: priv.(crypto.Signer), DNSKEY: key}, nil
}

func keyBits(alg uint8) int {
	switch alg {
	case dns.RSASHA256:
		return 2048
	case dns.ECDSAP256SHA256:
		return 256
	case dns.ED25519:
		return 256
	default:
		return 256
	}
}

// WriteKeyPair writes DNSKEY and private key in BIND-style format.
// pathPrefix is e.g. "/etc/gadget/ksk" -> writes ksk.key and ksk.private.
func WriteKeyPair(kp *KeyPair, pathPrefix string) error {
	base := filepath.Base(pathPrefix)
	if base == "." || base == "/" {
		base = "key"
	}
	dir := filepath.Dir(pathPrefix)
	if dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return err
		}
	}
	keyPath := filepath.Join(dir, base+".key")
	privatePath := filepath.Join(dir, base+".private")

	keyLine := kp.DNSKEY.String()
	if err := os.WriteFile(keyPath, []byte(keyLine+"\n"), 0644); err != nil {
		return err
	}
	privateStr := kp.DNSKEY.PrivateKeyString(kp.PrivateKey)
	if err := os.WriteFile(privatePath, []byte(privateStr), 0600); err != nil {
		return err
	}
	return nil
}

// LoadKeyPair loads a key pair from pathPrefix (reads pathPrefix.key and pathPrefix.private).
func LoadKeyPair(zone string, pathPrefix string, alg uint8, ksk bool) (*KeyPair, error) {
	_ = zone // zone is reserved for future use (e.g. key name validation)
	base := filepath.Base(pathPrefix)
	if base == "." || base == "/" {
		base = "key"
	}
	dir := filepath.Dir(pathPrefix)
	keyPath := filepath.Join(dir, base+".key")
	privatePath := filepath.Join(dir, base+".private")

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", keyPath, err)
	}
	rr, err := dns.NewRR(strings.TrimSpace(string(keyData)))
	if err != nil {
		return nil, fmt.Errorf("parse DNSKEY: %w", err)
	}
	dnskey, ok := rr.(*dns.DNSKEY)
	if !ok {
		return nil, fmt.Errorf("not a DNSKEY record")
	}
	// Optionally enforce algorithm
	if alg != 0 && dnskey.Algorithm != alg {
		return nil, fmt.Errorf("DNSKEY algorithm %d does not match requested %d", dnskey.Algorithm, alg)
	}

	privateData, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", privatePath, err)
	}
	priv, err := dnskey.ReadPrivateKey(strings.NewReader(string(privateData)), privatePath)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is not a crypto.Signer")
	}
	return &KeyPair{PrivateKey: signer, DNSKEY: dnskey}, nil
}

// SupportedAlgorithm returns true if alg is one of ALG8, ALG13, ALG15.
func SupportedAlgorithm(alg uint8) bool {
	return alg == dns.RSASHA256 || alg == dns.ECDSAP256SHA256 || alg == dns.ED25519
}
