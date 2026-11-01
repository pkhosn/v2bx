package node

import (
	"crypto/tls"
	"crypto/x509"
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
