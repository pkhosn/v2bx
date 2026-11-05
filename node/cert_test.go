package node

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/pkhosn/v2bx/conf"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func Test_generateSelfSslCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := generateSelfSslCertificate("example.com", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("example.com"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		t.Fatal("certificate is not currently valid")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatal(err)
	}
}

func TestSelfCertificateClosesFiles(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for i := 0; i < 2; i++ {
		if err := generateSelfSslCertificate("example.com", certPath, keyPath); err != nil {
			t.Fatal(err)
		}
		assertNoOpenFiles(t, dir)
		if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
			t.Fatal(err)
		}
	}
	if err := generateSelfSslCertificate("example.com", certPath, filepath.Join(dir, "missing", "key.pem")); err == nil {
		t.Fatal("missing key directory should fail")
	}
	assertNoOpenFiles(t, dir)
}

func TestEnsureCertificateReuseAndHostname(t *testing.T) {
	dir := t.TempDir()
	c := &conf.CertConfig{CertMode: "self", CertDomain: "example.com", CertFile: filepath.Join(dir, "nested", "cert.pem"), KeyFile: filepath.Join(dir, "nested", "key.pem")}
	if err := EnsureCertificate(c); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(c.CertFile)
	if err := EnsureCertificate(c); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(c.CertFile)
	if string(before) != string(after) {
		t.Fatal("valid certificate replaced")
	}
	c.CertDomain = "other.example.com"
	if ValidateCertificate(c) == nil {
		t.Fatal("hostname mismatch accepted")
	}
	c.CertMode = "file"
	if EnsureCertificate(c) == nil {
		t.Fatal("invalid provided certificate accepted")
	}
	c.CertMode = "self"
	if err := EnsureCertificate(c); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCertificate(c); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(c.KeyFile)
	if st.Mode().Perm() != 0600 {
		t.Fatal("private key permissions")
	}
}
