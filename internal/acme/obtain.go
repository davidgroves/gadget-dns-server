package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/davidgroves/gadget-dns-server/internal/logging"
	"golang.org/x/crypto/acme"
)

// Responder sets the HTTP-01 challenge response for a token.
type Responder interface {
	Set(token, response string)
}

// ObtainConfig holds options for obtaining a certificate.
type ObtainConfig struct {
	Domains          []string
	ACMEDirectoryURL string
	AccountKeyPath   string
	CertOutputPath   string
	KeyOutputPath    string
	Responder        Responder // required: use the running HTTP server's ACME responder
}

// Obtain runs the ACME HTTP-01 flow and writes cert+key. The responder must be
// served by an HTTP server on port 80 (or the challenge will fail).
func Obtain(ctx context.Context, cfg ObtainConfig) error {
	if len(cfg.Domains) == 0 {
		return fmt.Errorf("acme: at least one domain required")
	}
	if cfg.CertOutputPath == "" || cfg.KeyOutputPath == "" {
		return fmt.Errorf("acme: cert and key output paths required")
	}
	if cfg.Responder == nil {
		return fmt.Errorf("acme: responder is required (HTTP server must be running)")
	}
	dirURL := cfg.ACMEDirectoryURL
	if dirURL == "" {
		dirURL = acme.LetsEncryptURL
	}

	accountKey, err := loadOrCreateAccountKey(cfg.AccountKeyPath)
	if err != nil {
		return fmt.Errorf("acme account key: %w", err)
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: dirURL}
	if _, err := client.Discover(ctx); err != nil {
		return fmt.Errorf("acme discover: %w", err)
	}
	_, err = client.Register(ctx, &acme.Account{}, acme.AcceptTOS)
	if err != nil && err != acme.ErrAccountAlreadyExists {
		return fmt.Errorf("acme register: %w", err)
	}
	logging.Info("ACME order created", "domains", cfg.Domains)

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(cfg.Domains...))
	if err != nil {
		return fmt.Errorf("acme authorize order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("acme get authorization: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		if authz.Status != acme.StatusPending {
			return fmt.Errorf("acme authorization %s status %s", authz.URI, authz.Status)
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return fmt.Errorf("acme: no http-01 challenge for %s", authz.URI)
		}
		response, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return fmt.Errorf("acme challenge response: %w", err)
		}
		cfg.Responder.Set(chal.Token, response)
		if _, err := client.Accept(ctx, chal); err != nil {
			return fmt.Errorf("acme accept challenge: %w", err)
		}
		logging.Info("ACME HTTP-01 challenge accepted", "domain", authz.Identifier.Value)
		authz, err = client.WaitAuthorization(ctx, authz.URI)
		if err != nil {
			return fmt.Errorf("acme wait authorization: %w", err)
		}
		if authz.Status != acme.StatusValid {
			return fmt.Errorf("acme authorization failed: status %s", authz.Status)
		}
	}

	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		if d, ok := acme.RateLimit(err); ok {
			return fmt.Errorf("acme rate limited: retry after %v: %w", d, err)
		}
		return fmt.Errorf("acme wait order: %w", err)
	}
	if order.Status != acme.StatusReady && order.Status != acme.StatusValid {
		return fmt.Errorf("acme order status %s", order.Status)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("acme generate cert key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cfg.Domains[0]},
		DNSNames: cfg.Domains,
	}, certKey)
	if err != nil {
		return fmt.Errorf("acme create CSR: %w", err)
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return fmt.Errorf("acme create order cert: %w", err)
	}
	if err := writeCertPEM(cfg.CertOutputPath, der); err != nil {
		return fmt.Errorf("acme write cert: %w", err)
	}
	if err := writeKeyPEM(cfg.KeyOutputPath, certKey); err != nil {
		return fmt.Errorf("acme write key: %w", err)
	}
	logging.Info("Certificate written", "cert", cfg.CertOutputPath, "key", cfg.KeyOutputPath)
	return nil
}

func loadOrCreateAccountKey(path string) (crypto.Signer, error) {
	if path == "" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no PEM block in account key file")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			keyRSA, errRSA := x509.ParsePKCS1PrivateKey(block.Bytes)
			if errRSA != nil {
				keyAny, errPKCS8 := x509.ParsePKCS8PrivateKey(block.Bytes)
				if errPKCS8 != nil {
					return nil, fmt.Errorf("parse account key: %w", err)
				}
				signer, ok := keyAny.(crypto.Signer)
				if !ok {
					return nil, fmt.Errorf("account key is not a supported signer type")
				}
				return signer, nil
			}
			return keyRSA, nil
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeKeyPEM(path, key); err != nil {
		return nil, err
	}
	logging.Info("Created new ACME account key", "path", path)
	return key, nil
}

func writeCertPEM(path string, der [][]byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, b := range der {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: b}); err != nil {
			return err
		}
	}
	return nil
}

func writeKeyPEM(path string, key interface{}) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600)
}

// CertExpiry returns the expiry time of the first cert in the PEM file, or zero time if invalid.
func CertExpiry(certPath string) (time.Time, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}
