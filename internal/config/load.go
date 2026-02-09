package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadYAML loads config from path (merge into c). No-op if path is empty or file missing.
func LoadYAML(c *Config, path string) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var overlay Config
	if err := yaml.Unmarshal(data, &overlay); err != nil {
		return fmt.Errorf("yaml: %w", err)
	}
	merge(c, &overlay)
	return nil
}

// merge overlays non-zero values from b onto a.
func merge(a, b *Config) {
	if b.Domain != "" {
		a.Domain = b.Domain
	}
	if b.Ports.UDP != 0 {
		a.Ports.UDP = b.Ports.UDP
	}
	if b.Ports.TCP != 0 {
		a.Ports.TCP = b.Ports.TCP
	}
	if b.Ports.DoT != 0 {
		a.Ports.DoT = b.Ports.DoT
	}
	if b.Ports.DoH != 0 {
		a.Ports.DoH = b.Ports.DoH
	}
	if b.Ports.DoQ != 0 {
		a.Ports.DoQ = b.Ports.DoQ
	}
	if len(b.Binds) > 0 {
		a.Binds = append([]string(nil), b.Binds...)
	}
	if b.TLSCert != "" {
		a.TLSCert = b.TLSCert
	}
	if b.TLSKey != "" {
		a.TLSKey = b.TLSKey
	}
	if len(b.NSRecords) > 0 {
		a.NSRecords = b.NSRecords
	}
	if len(b.ServerIPs) > 0 {
		a.ServerIPs = b.ServerIPs
	}
	if b.SOAMname != "" {
		a.SOAMname = b.SOAMname
	}
	if b.SOARname != "" {
		a.SOARname = b.SOARname
	}
	if b.SOASerial != 0 {
		a.SOASerial = b.SOASerial
	}
	if b.SOARefresh != 0 {
		a.SOARefresh = b.SOARefresh
	}
	if b.SOARetry != 0 {
		a.SOARetry = b.SOARetry
	}
	if b.SOAExpire != 0 {
		a.SOAExpire = b.SOAExpire
	}
	if b.SOAMinttl != 0 {
		a.SOAMinttl = b.SOAMinttl
	}
	if b.HTTPPort != 0 {
		a.HTTPPort = b.HTTPPort
	}
	if b.HTTPTLSPort != 0 {
		a.HTTPTLSPort = b.HTTPTLSPort
	}
	if len(b.ACMEDomains) > 0 {
		a.ACMEDomains = b.ACMEDomains
	}
	if len(b.ACMEIPs) > 0 {
		a.ACMEIPs = b.ACMEIPs
	}
	if b.ACMEAccountKey != "" {
		a.ACMEAccountKey = b.ACMEAccountKey
	}
	if b.ACMEURL != "" {
		a.ACMEURL = b.ACMEURL
	}
	if b.ACMERenewDays != 0 {
		a.ACMERenewDays = b.ACMERenewDays
	}
	if b.LogLevel != "" {
		a.LogLevel = b.LogLevel
	}
	if b.LogOutput != "" {
		a.LogOutput = b.LogOutput
	}
	if b.DNSSEC {
		a.DNSSEC = true
	}
	if b.DNSSECKSKPath != "" {
		a.DNSSECKSKPath = b.DNSSECKSKPath
	}
	if b.DNSSECZSKPath != "" {
		a.DNSSECZSKPath = b.DNSSECZSKPath
	}
	if b.DNSSECPublishCDS {
		a.DNSSECPublishCDS = true
	}
	if b.DNSSECRRSIGInception != "" {
		a.DNSSECRRSIGInception = b.DNSSECRRSIGInception
	}
	if b.DNSSECRRSIGValidity != "" {
		a.DNSSECRRSIGValidity = b.DNSSECRRSIGValidity
	}
	if b.DiagRetention != "" {
		a.DiagRetention = b.DiagRetention
	}
}
