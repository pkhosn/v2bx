package node

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/pkhosn/v2bx/conf"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

var certificateMu sync.Mutex

func (c *Controller) renewCertTask() error {
	certificateMu.Lock()
	defer certificateMu.Unlock()
	l, err := NewLego(c.CertConfig)
	if err != nil {
		log.WithField("tag", c.tag).Info("new lego error: ", err)
		return nil
	}
	err = l.RenewCert()
	if err != nil {
		log.WithField("tag", c.tag).Info("renew cert error: ", err)
		return nil
	}
	return nil
}

func (c *Controller) requestCert() error {
	return EnsureCertificate(c.CertConfig)
}

// ValidateCertificate checks the key pair, validity and configured hostname.
// Trust is deliberately left to clients (file and self modes support private CAs).
func ValidateCertificate(c *conf.CertConfig) error {
	pair, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return fmt.Errorf("certificate is not currently valid")
	}
	if c.CertDomain != "" {
		return leaf.VerifyHostname(c.CertDomain)
	}
	return nil
}

// EnsureCertificate reuses valid certificates and prepares replacements before
// touching existing files. Callers can preflight TLS before saving node config.
func EnsureCertificate(c *conf.CertConfig) error {
	certificateMu.Lock()
	defer certificateMu.Unlock()
	if c == nil {
		return fmt.Errorf("missing certificate configuration")
	}
	switch c.CertMode {
	case "none", "":
		return nil
	case "file":
		return ValidateCertificate(c)
	case "http", "dns", "self":
	default:
		return fmt.Errorf("unsupported certmode: %s", c.CertMode)
	}
	if c.CertFile == "" || c.KeyFile == "" || c.CertFile == c.KeyFile {
		return fmt.Errorf("distinct certificate and key paths are required")
	}
	if err := ValidateCertificate(c); err == nil {
		return nil
	}
	if c.CertDomain == "" {
		return fmt.Errorf("certificate domain is required")
	}
	for _, p := range []string{c.CertFile, c.KeyFile} {
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return err
		}
	}
	staged := *c
	dir, err := os.MkdirTemp(filepath.Dir(c.CertFile), ".certificate-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	staged.CertFile = filepath.Join(dir, "fullchain.cer")
	staged.KeyFile = filepath.Join(dir, "cert.key")
	if c.CertMode == "self" {
		err = generateSelfSslCertificate(c.CertDomain, staged.CertFile, staged.KeyFile)
	} else {
		// Keep the persistent ACME account beside the final certificate.
		var l *Lego
		l, err = NewLego(c)
		if err == nil {
			l.config = &staged
			err = l.CreateCert()
		}
	}
	if err != nil {
		return err
	}
	if err = ValidateCertificate(&staged); err != nil {
		return err
	}
	cert, err := os.ReadFile(staged.CertFile)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(staged.KeyFile)
	if err != nil {
		return err
	}
	// Prepare both destinations before replacing either file.
	certTemp, err := stageCertificateFile(c.CertFile, cert, 0644)
	if err != nil {
		return err
	}
	defer os.Remove(certTemp)
	keyTemp, err := stageCertificateFile(c.KeyFile, key, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(keyTemp)
	if err = os.Rename(keyTemp, c.KeyFile); err != nil {
		return err
	}
	return os.Rename(certTemp, c.CertFile)
}

func stageCertificateFile(destination string, data []byte, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(destination), ".cert-write-")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func generateSelfSslCertificate(domain, certPath, keyPath string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(30, 0, 0),
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: cert,
	}), 0644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0600)
}
