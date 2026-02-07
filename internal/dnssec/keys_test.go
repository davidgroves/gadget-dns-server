package dnssec

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func TestGenerateKeyPair_ALG8(t *testing.T) {
	kp, err := GenerateKeyPair("example.com.", dns.RSASHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	if kp.DNSKEY.Algorithm != dns.RSASHA256 {
		t.Errorf("algorithm=%d want 8", kp.DNSKEY.Algorithm)
	}
	if kp.DNSKEY.Flags&dns.SEP == 0 {
		t.Error("KSK should have SEP bit")
	}
	if kp.DNSKEY.KeyTag() == 0 {
		t.Error("KeyTag should be non-zero")
	}
}

func TestGenerateKeyPair_ALG13(t *testing.T) {
	kp, err := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	if kp.DNSKEY.Algorithm != dns.ECDSAP256SHA256 {
		t.Errorf("algorithm=%d want 13", kp.DNSKEY.Algorithm)
	}
	if kp.DNSKEY.Flags&dns.SEP != 0 {
		t.Error("ZSK should not have SEP bit")
	}
}

func TestGenerateKeyPair_ALG15(t *testing.T) {
	kp, err := GenerateKeyPair("example.com.", dns.ED25519, true)
	if err != nil {
		t.Fatal(err)
	}
	if kp.DNSKEY.Algorithm != dns.ED25519 {
		t.Errorf("algorithm=%d want 15", kp.DNSKEY.Algorithm)
	}
}

func TestWriteAndLoadKeyPair(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "ksk")
	kp, err := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteKeyPair(kp, prefix); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadKeyPair("example.com.", prefix, dns.ECDSAP256SHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DNSKEY.KeyTag() != kp.DNSKEY.KeyTag() {
		t.Errorf("KeyTag after load=%d want %d", loaded.DNSKEY.KeyTag(), kp.DNSKEY.KeyTag())
	}
}

func TestLoadKeyPair_NoFile(t *testing.T) {
	_, err := LoadKeyPair("example.com.", filepath.Join(t.TempDir(), "nonexistent"), dns.ECDSAP256SHA256, true)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSupportedAlgorithm(t *testing.T) {
	if !SupportedAlgorithm(dns.RSASHA256) {
		t.Error("ALG8 should be supported")
	}
	if !SupportedAlgorithm(dns.ECDSAP256SHA256) {
		t.Error("ALG13 should be supported")
	}
	if !SupportedAlgorithm(dns.ED25519) {
		t.Error("ALG15 should be supported")
	}
	if SupportedAlgorithm(99) {
		t.Error("unknown alg should not be supported")
	}
}

func TestKeyPair_ToDS(t *testing.T) {
	kp, _ := GenerateKeyPair("example.com.", dns.ECDSAP256SHA256, true)
	ds := kp.DNSKEY.ToDS(dns.SHA256)
	if ds == nil {
		t.Fatal("ToDS returned nil")
	}
	if ds.Algorithm != dns.ECDSAP256SHA256 {
		t.Errorf("DS algorithm=%d", ds.Algorithm)
	}
}

func TestWriteKeyPair_CreatesDir(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "sub", "key")
	kp, _ := GenerateKeyPair("example.com.", dns.ED25519, false)
	err := WriteKeyPair(kp, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sub", "key.key")); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sub", "key.private")); err != nil {
		t.Error(err)
	}
}
