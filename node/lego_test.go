package node

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/pkhosn/v2bx/conf"
)

func testCertificate(t *testing.T, lifetime time.Duration) *certificate.Resource {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(lifetime),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := EncodePrivate(key)
	if err != nil {
		t.Fatal(err)
	}
	return &certificate.Resource{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:  []byte(encodedKey),
	}
}

func TestLego_CheckCert(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lifetime  time.Duration
		wantRenew bool
	}{
		{"valid", 90 * 24 * time.Hour, false},
		{"near_expiry", 15 * 24 * time.Hour, true},
		{"expired", -time.Hour, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			renew, err := (&Lego{}).CheckCert(testCertificate(t, tc.lifetime).Certificate)
			if err != nil || renew != tc.wantRenew {
				t.Fatalf("CheckCert = %v, %v; want %v, nil", renew, err, tc.wantRenew)
			}
		})
	}
	if _, err := (&Lego{}).CheckCert([]byte("invalid certificate")); err == nil {
		t.Fatal("invalid certificate should return an error")
	}
}

func TestLego_RenewCert(t *testing.T) {
	for _, scenario := range []string{"valid", "missing", "invalid"} {
		t.Run(scenario, func(t *testing.T) {
			certPath := filepath.Join(t.TempDir(), "cert.pem")
			var original []byte
			if scenario != "missing" {
				original = []byte("invalid certificate")
				if scenario == "valid" {
					original = testCertificate(t, 90*24*time.Hour).Certificate
				}
				if err := os.WriteFile(certPath, original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			// No ACME client: a valid long-lived certificate must skip renewal locally.
			l := &Lego{config: &conf.CertConfig{CertFile: certPath}}
			err := l.RenewCert()
			if (err != nil) != (scenario != "valid") {
				t.Fatalf("RenewCert = %v for %s", err, scenario)
			}
			if scenario != "missing" {
				actual, err := os.ReadFile(certPath)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(actual, original) {
					t.Fatal("certificate changed without renewal")
				}
			}
		})
	}
}

func TestLego_WriteCert(t *testing.T) {
	dir := t.TempDir()
	l := &Lego{config: &conf.CertConfig{
		CertDomain: "example.com", Email: "admin@example.com",
		CertFile: filepath.Join(dir, "certs", "{domain}.pem"),
		KeyFile:  filepath.Join(dir, "keys", "{email}.key"),
	}}
	resource := testCertificate(t, 90*24*time.Hour)
	if err := l.writeCert(resource); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][]byte{
		filepath.Join(dir, "certs", "example.com.pem"):      resource.Certificate,
		filepath.Join(dir, "keys", "admin@example.com.key"): resource.PrivateKey,
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("unexpected contents in %s", path)
		}
	}
}

func TestLegoUser_SaveLoad(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	original := &User{Email: "admin@example.com", key: key}
	path := filepath.Join(t.TempDir(), "user", "account.json")
	if err := original.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := NewLegoUser(path, original.Email)
	if err != nil {
		t.Fatal(err)
	}
	restored, ok := loaded.GetPrivateKey().(*ecdsa.PrivateKey)
	if !ok || !key.Equal(restored) || loaded.GetEmail() != original.Email {
		t.Fatal("account email or private key did not survive save/load")
	}
}

func TestUser_DecodePrivateRejectsInvalidPEM(t *testing.T) {
	for _, body := range []string{"", "not PEM", "-----BEGIN EC PRIVATE KEY-----\nbroken\n-----END EC PRIVATE KEY-----", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("invalid DER")}))} {
		if _, err := (&User{}).DecodePrivate(body); err == nil {
			t.Fatal("invalid key should return an error")
		}
	}
	path := filepath.Join(t.TempDir(), "account.json")
	if err := os.WriteFile(path, []byte(`{"Email":"admin@example.com","Key":"broken"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLegoUser(path, "admin@example.com"); err == nil {
		t.Fatal("corrupt account should fail locally")
	}
}

func assertNoOpenFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("file descriptor check requires procfs")
	}
	for _, entry := range entries {
		target, _ := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		relative, err := filepath.Rel(dir, target)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			t.Errorf("file descriptor still open: %s", target)
		}
	}
}

func TestUser_SaveClosesFiles(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	user := &User{Email: "admin@example.com", key: key}
	for i := 0; i < 5; i++ {
		if err := user.Save(filepath.Join(dir, "account.json")); err != nil {
			t.Fatal(err)
		}
		assertNoOpenFiles(t, dir)
	}
	if user.KeyEncoded != "" {
		t.Fatal("Save retained encoded private key")
	}
}
