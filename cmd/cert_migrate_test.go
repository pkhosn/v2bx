package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkhosn/v2bx/api/panel"
	"github.com/pkhosn/v2bx/conf"
	"github.com/pkhosn/v2bx/node"
)

func migrationFixture(t *testing.T) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	c := &conf.CertConfig{CertMode: "self", CertDomain: "node.example.com", CertFile: filepath.Join(dir, "fullchain.cer"), KeyFile: filepath.Join(dir, "cert.key"), Email: "admin@example.com"}
	if err := node.EnsureCertificate(c); err != nil {
		t.Fatal(err)
	}
	c.CertMode = "http"
	fields := map[string]any{"CertConfig": c, "Custom": "keep"}
	data, err := json.Marshal(map[string]any{"Future": 9007199254740993, "Cores": []any{}, "Nodes": []any{fields, map[string]any{"Options": fields}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(dir, "user"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "user", "user-admin@example.com.json"), []byte(`{"account":"preserve"}`), 0600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

func TestCertificateMigrationPreviewApplyAndRepeat(t *testing.T) {
	path, original := migrationFixture(t)
	dir := filepath.Dir(path)
	target := filepath.Join(dir, "certs", "acme", "node.example.com")
	var out bytes.Buffer
	if err := migrateCertificates(path, false, &out); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(path)
	if !bytes.Equal(current, original) {
		t.Fatal("preview modified config")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("preview created target")
	}
	if err := migrateCertificates(path, true, &out); err != nil {
		t.Fatal(err)
	}
	backup, _ := os.ReadFile(path + ".bak")
	if !bytes.Equal(backup, original) {
		t.Fatal("backup differs")
	}
	for _, name := range []string{"fullchain.cer", "cert.key", "user/user-admin@example.com.json"} {
		old, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		copied, err := os.ReadFile(filepath.Join(target, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(old, copied) {
			t.Fatal("changed certificate or account")
		}
		if name != "fullchain.cer" {
			st, _ := os.Stat(filepath.Join(target, name))
			if st.Mode().Perm() != 0600 {
				t.Fatal("private file permissions")
			}
		}
	}
	current, _ = os.ReadFile(path)
	d, err := readDocument(current)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range d.parsed {
		if n.Options.CertConfig.CertFile != filepath.Join(target, "fullchain.cer") {
			t.Fatal("node path not migrated")
		}
	}
	if strings.Count(string(current), "keep") != 2 {
		t.Fatal("unknown fields lost")
	}
	if err = migrateCertificates(path, true, &out); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(path)
	if !bytes.Equal(current, again) {
		t.Fatal("repeat changed config")
	}
}

func TestCertificateMigrationRejectsInvalidAndExistingTarget(t *testing.T) {
	for _, reason := range []string{"invalid", "existing", "manual"} {
		t.Run(reason, func(t *testing.T) {
			path, original := migrationFixture(t)
			dir := filepath.Dir(path)
			switch reason {
			case "invalid":
				original = bytes.ReplaceAll(original, []byte(`"CertDomain":"node.example.com"`), []byte(`"CertDomain":"wrong.example.com"`))
				os.WriteFile(path, original, 0600)
			case "existing":
				os.MkdirAll(filepath.Join(dir, "certs", "acme", "node.example.com"), 0700)
			case "manual":
				original = bytes.ReplaceAll(original, []byte(`"CertMode":"http"`), []byte(`"CertMode":"file"`))
				os.WriteFile(path, original, 0600)
			}
			var out bytes.Buffer
			err := migrateCertificates(path, true, &out)
			if reason == "manual" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unsafe migration accepted")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, original) {
				t.Fatal("config changed")
			}
			if _, e := os.Stat(path + ".bak"); !os.IsNotExist(e) {
				t.Fatal("backup should not exist")
			}
		})
	}
}

type migrationWriter func([]byte) (int, error)

func (f migrationWriter) Write(b []byte) (int, error) { return f(b) }

func TestCertificateMigrationRollsBackWhenConfigChanges(t *testing.T) {
	path, original := migrationFixture(t)
	changed := append(append([]byte{}, original...), '\n')
	out := migrationWriter(func(b []byte) (int, error) {
		if err := os.WriteFile(path, changed, 0600); err != nil {
			return 0, err
		}
		return len(b), nil
	})
	if err := migrateCertificates(path, true, out); err == nil {
		t.Fatal("concurrent configuration change accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, changed) {
		t.Fatal("concurrent change overwritten")
	}
	target := filepath.Join(filepath.Dir(path), "certs", "acme", "node.example.com")
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("failed migration left destination")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "cert.key")); err != nil {
		t.Fatal("source key removed")
	}
}

func TestHTTPWizardFirstNodeUsesDomainDirectory(t *testing.T) {
	input := strings.NewReader("1\nnode.example.com\n\n")
	dir := t.TempDir()
	w := &nodeWizard{input: input, in: bufio.NewReader(input), out: &bytes.Buffer{}}
	c, err := w.certificate(&panel.NodeInfo{Security: panel.Tls}, &configDocument{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.CertMode != "http" || c.CertFile != filepath.Join(dir, "certs", "acme", "node.example.com", "fullchain.cer") || c.KeyFile != filepath.Join(dir, "certs", "acme", "node.example.com", "cert.key") {
		t.Fatal("first node uses legacy paths")
	}
}

func TestCertificateMigrationDNSWithoutAccount(t *testing.T) {
	path, data := migrationFixture(t)
	data = bytes.ReplaceAll(data, []byte(`"CertMode":"http"`), []byte(`"CertMode":"dns"`))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(path), "user", "user-admin@example.com.json")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := migrateCertificates(path, true, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "无本地 ACME 账户") {
		t.Fatal("missing account silently ignored")
	}
}
