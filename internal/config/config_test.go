package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseServerIPs(t *testing.T) {
	ips, err := ParseServerIPs("192.168.1.1, 10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("len(ips)=%d want 2", len(ips))
	}
	if ips[0].String() != "192.168.1.1" || ips[1].String() != "10.0.0.1" {
		t.Errorf("ips=%v", ips)
	}
}

func TestParseServerIPs_Empty(t *testing.T) {
	ips, err := ParseServerIPs("")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 0 {
		t.Errorf("len(ips)=%d", len(ips))
	}
}

func TestParseServerIPs_Invalid(t *testing.T) {
	_, err := ParseServerIPs("not-an-ip")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestConfig_Validate_ObtainCert(t *testing.T) {
	c := DefaultConfig()
	c.ObtainCert = true
	c.ACMEDomains = []string{"example.com"}
	c.TLSCert = "/tmp/cert.pem"
	c.TLSKey = "/tmp/key.pem"
	if err := c.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestConfig_Validate_ObtainCert_MissingDomain(t *testing.T) {
	c := DefaultConfig()
	c.ObtainCert = true
	c.TLSCert = "/tmp/cert.pem"
	c.TLSKey = "/tmp/key.pem"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestConfig_Validate_Server_RequiresDomain(t *testing.T) {
	c := DefaultConfig()
	c.Domain = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestConfig_SetFromEnv(t *testing.T) {
	os.Setenv("GADGET_DOMAIN", "test.example.com")
	os.Setenv("GADGET_HTTP_PORT", "8080")
	defer os.Unsetenv("GADGET_DOMAIN")
	defer os.Unsetenv("GADGET_HTTP_PORT")
	c := DefaultConfig()
	if err := c.SetFromEnv(); err != nil {
		t.Fatal(err)
	}
	if c.Domain != "test.example.com" {
		t.Errorf("Domain=%q", c.Domain)
	}
	if c.HTTPPort != 8080 {
		t.Errorf("HTTPPort=%d", c.HTTPPort)
	}
}

func TestLoadYAML_NotFound(t *testing.T) {
	c := DefaultConfig()
	err := LoadYAML(&c, filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err != nil {
		t.Errorf("LoadYAML nonexistent should not error: %v", err)
	}
}

func TestParseRRSIGDuration(t *testing.T) {
	if d := ParseRRSIGDuration("1h", time.Minute); d != time.Hour {
		t.Errorf("ParseRRSIGDuration(1h)=%v want 1h", d)
	}
	if d := ParseRRSIGDuration("24h", time.Minute); d != 24*time.Hour {
		t.Errorf("ParseRRSIGDuration(24h)=%v", d)
	}
	if d := ParseRRSIGDuration("", time.Hour); d != time.Hour {
		t.Errorf("ParseRRSIGDuration(empty)=%v want default 1h", d)
	}
	if d := ParseRRSIGDuration("invalid", time.Hour); d != time.Hour {
		t.Errorf("ParseRRSIGDuration(invalid)=%v want default 1h", d)
	}
}

func TestLoadYAML_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := []byte("domain: yaml.example.com\nhttp_port: 9000\n")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
	c := DefaultConfig()
	if err := LoadYAML(&c, path); err != nil {
		t.Fatal(err)
	}
	if c.Domain != "yaml.example.com" {
		t.Errorf("Domain=%q", c.Domain)
	}
	if c.HTTPPort != 9000 {
		t.Errorf("HTTPPort=%d", c.HTTPPort)
	}
}
