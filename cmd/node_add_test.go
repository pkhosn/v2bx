package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkhosn/v2bx/api/panel"
	"github.com/pkhosn/v2bx/conf"
	"github.com/pkhosn/v2bx/core"
)

func TestAppendPreservesConfiguration(t *testing.T) {
	original := []byte(`{// comment
 "Future":{"precise":9007199254740993},"Cores":[{"Type":"xray","Name":"primary","Custom":true}],
 "Nodes":[{"ApiHost":"https://panel.example","ApiKey":"old","NodeID":1,"NodeType":"vmess","Custom":"keep"}],}`)
	d, err := readDocument(original)
	if err != nil {
		t.Fatal(err)
	}
	a := conf.ApiConfig{APIHost: "https://panel.example/", NodeType: "vmess", NodeID: 1}
	if d.checkDuplicate(a) == nil {
		t.Fatal("duplicate accepted")
	}
	a.NodeID = 2
	if err = d.appendNode(a, "xray", conf.NewCertConfig()); err != nil {
		t.Fatal(err)
	}
	a.NodeID = 3
	a.NodeType = "hysteria2"
	if err = d.appendNode(a, "sing", conf.NewCertConfig()); err != nil {
		t.Fatal(err)
	}
	data, err := d.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(d.nodes) != 3 || len(d.cores) != 2 {
		t.Fatal("nodes/cores lost")
	}
	for _, s := range []string{"9007199254740993", `"Custom": "keep"`, `"Custom": true`, `"CoreName": "primary"`} {
		if !bytes.Contains(data, []byte(s)) {
			t.Fatalf("missing %s: %s", s, data)
		}
	}
	var config conf.Conf
	if err = json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if config.NodeConfig[2].Options.Core != "sing" {
		t.Fatal("wrong core")
	}
}
func TestSaveDocumentBackupAndConcurrentEdit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	old := []byte("old")
	os.WriteFile(p, old, 0644)
	if err := saveDocument(p, old, []byte("new")); err != nil {
		t.Fatal(err)
	}
	backup, _ := os.ReadFile(p + ".bak")
	if !bytes.Equal(backup, old) {
		t.Fatal("bad backup")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0600 {
		t.Fatal("credentials exposed")
	}
	if saveDocument(p, old, []byte("bad")) == nil {
		t.Fatal("concurrent edit overwritten")
	}
	current, _ := os.ReadFile(p)
	if string(current) != "new" {
		t.Fatal("changed after failure")
	}
}
func TestWizardFailureNeverSaves(t *testing.T) {
	registered := core.RegisteredCore()
	if len(registered) == 0 {
		t.Skip("no compiled core")
	}
	c := registered[0]
	protocol := "vmess"
	if c == "hysteria2" {
		protocol = "hysteria2"
	}
	for _, failure := range []string{"panel", "cert", "eof"} {
		t.Run(failure, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.json")
			original := []byte(`{"Cores":[],"Nodes":[],"Future":true}`)
			os.WriteFile(p, original, 0600)
			input := "https://panel.example\nsecret\n" + protocol + "\n1\n" + c + "\n"
			if failure == "cert" {
				input += "example.com\n3\n"
			}
			r := strings.NewReader(input)
			w := &nodeWizard{input: r, in: bufio.NewReader(r), out: &bytes.Buffer{}, fetch: func(*conf.ApiConfig) (*panel.NodeInfo, error) {
				if failure == "panel" {
					return nil, fmt.Errorf("unavailable")
				}
				security := panel.None
				if failure == "cert" {
					security = panel.Tls
				}
				return &panel.NodeInfo{Security: security}, nil
			}, ensure: func(*conf.CertConfig) error {
				if failure == "cert" {
					return fmt.Errorf("ACME failed")
				}
				return nil
			}}
			if w.run(p, false) == nil {
				t.Fatal("expected failure")
			}
			after, _ := os.ReadFile(p)
			if !bytes.Equal(original, after) {
				t.Fatal("old config modified")
			}
		})
	}
}
func TestCertificateSecurityAndInput(t *testing.T) {
	for _, security := range []int{panel.None, panel.Reality} {
		w := &nodeWizard{}
		c, err := w.certificate(&panel.NodeInfo{Security: security}, &configDocument{}, t.TempDir())
		if err != nil || c.CertMode != "none" {
			t.Fatal("unexpected certificate prompt")
		}
	}
	for _, s := range []string{"../example.com", "https://example.com", "*.example.com", "example.com/foo", "-a.example.com", "127.0.0.1"} {
		if validDomain(s) {
			t.Fatal("unsafe domain", s)
		}
	}
}

func TestWizardSuccessfulAppend(t *testing.T) {
	registered := core.RegisteredCore()
	if len(registered) == 0 {
		t.Skip("no compiled core")
	}
	c := registered[0]
	protocol := "vmess"
	if c == "hysteria2" {
		protocol = "hysteria2"
	}
	p := filepath.Join(t.TempDir(), "config.json")
	original := []byte(`{"Cores":[],"Nodes":[],"Future":{"enabled":true}}`)
	os.WriteFile(p, original, 0600)
	r := strings.NewReader("https://panel.example\nsecret\n" + protocol + "\n1\n" + c + "\nn\n")
	w := &nodeWizard{input: r, in: bufio.NewReader(r), out: &bytes.Buffer{}, fetch: func(a *conf.ApiConfig) (*panel.NodeInfo, error) {
		if a.Key != "secret" || a.NodeID != 1 {
			t.Fatal("wrong panel request")
		}
		return &panel.NodeInfo{Security: panel.Reality}, nil
	}, ensure: func(c *conf.CertConfig) error {
		if c.CertMode != "none" {
			t.Fatal("REALITY requires no certificate")
		}
		return nil
	}}
	if err := w.run(p, false); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	d, err := readDocument(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.nodes) != 1 || len(d.cores) != 1 || d.fields["Future"] == nil {
		t.Fatal("bad appended config")
	}
	backup, _ := os.ReadFile(p + ".bak")
	if !bytes.Equal(original, backup) {
		t.Fatal("bad backup")
	}
}
func TestDNSWizardCapturesCredentials(t *testing.T) {
	r := strings.NewReader("node.example.com\n2\nadmin@example.com\nprivate-token\n")
	w := &nodeWizard{input: r, in: bufio.NewReader(r), out: &bytes.Buffer{}}
	c, err := w.certificate(&panel.NodeInfo{Security: panel.Tls}, &configDocument{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if c.CertMode != "dns" || c.DNSEnv["CF_DNS_API_TOKEN"] != "private-token" || !strings.Contains(c.CertFile, "/acme/node.example.com/") {
		t.Fatal("bad DNS configuration")
	}
	if strings.Contains(w.out.(*bytes.Buffer).String(), "private-token") {
		t.Fatal("token exposed")
	}
}

func TestAppendPinsImplicitSingleCore(t *testing.T) {
	d, err := readDocument([]byte(`{"Cores":[{"Type":"xray","Name":"original"}],"Nodes":[{"ApiHost":"https://panel.example","NodeType":"vmess","NodeID":1,"Unknown":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = d.appendNode(conf.ApiConfig{APIHost: "https://panel.example", NodeType: "hysteria2", NodeID: 2}, "sing", conf.NewCertConfig()); err != nil {
		t.Fatal(err)
	}
	var old conf.NodeConfig
	if err = json.Unmarshal(d.nodes[0], &old); err != nil {
		t.Fatal(err)
	}
	if old.Options.Core != "xray" || old.Options.CoreName != "original" {
		t.Fatal("old node core selection changed")
	}
}
