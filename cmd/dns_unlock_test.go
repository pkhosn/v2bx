package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestUnlockAddress(t *testing.T) {
	for _, s := range []string{"4.4.4.4", "tcp://4.4.4.4", "udp://4.4.4.4:5353", "2001:4860:4860::8888"} {
		if _, e := unlockAddress(s); e != nil {
			t.Fatal(s, e)
		}
	}
	for _, s := range []string{"4.4.4.4（以实际显示为准）", "https://example.com/dns-query", "tcp://127.0.0.1:0", "tcp://4.4.4.4:65536", "tcp://user@4.4.4.4", "tcp://4.4.4.4/path", "udp://0.0.0.0"} {
		if _, e := unlockAddress(s); e == nil {
			t.Fatal("invalid DNS accepted", s)
		}
	}
}
func unlockFixture(t *testing.T) (string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{"Future":{"keep":true},"Cores":[{"Type":"sing","Name":"s"},{"Type":"xray","Name":"x"}],"Nodes":[{"ApiHost":"https://panel","NodeType":"vmess","NodeID":1,"Core":"sing","CoreName":"s","Custom":123},{"ApiConfig":{"ApiHost":"https://panel","NodeType":"vless","NodeID":2},"Options":{"Core":"xray","CoreName":"x","SendIP":"::","Custom":456}}]}`)
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	return path, data
}
func TestUnlockMixedCoreMergeAndRestore(t *testing.T) {
	path, _ := unlockFixture(t)
	data, _ := os.ReadFile(path)
	d, e := readDocument(data)
	if e != nil {
		t.Fatal(e)
	}
	state, files, e := prepareUnlock(d, filepath.Join(filepath.Dir(path), "managed"), "tcp://4.4.4.4:53")
	if e != nil {
		t.Fatal(e)
	}
	if len(files) != 2 || len(state.Patches) != 3 {
		t.Fatal("missing core/node updates")
	}
	raw, _ := d.marshal()
	if !bytes.Contains(raw, []byte(`"EnableDNS": true`)) || !bytes.Contains(raw, []byte(`"DNSType": "UseIP"`)) {
		t.Fatal("missing xray fields")
	}
	// Unrelated edits and later-added nodes survive disable.
	m, _ := unlockObject(d.nodes[0])
	m["NewField"] = unlockRaw("keep")
	d.nodes[0] = unlockRaw(m)
	d.nodes = append(d.nodes, unlockRaw(map[string]any{"ApiHost": "https://panel", "NodeType": "vmess", "NodeID": 3, "Core": "sing", "CoreName": "s"}))
	if e = restoreUnlock(d, state); e != nil {
		t.Fatal(e)
	}
	raw, _ = d.marshal()
	if !bytes.Contains(raw, []byte(`"SendIP": "::"`)) || bytes.Contains(raw, []byte(`"EnableDNS"`)) || !bytes.Contains(raw, []byte(`"NewField": "keep"`)) || len(d.nodes) != 3 {
		t.Fatal("restore lost data", string(raw))
	}
}
func TestUnlockRestoreRejectsConflictingEdit(t *testing.T) {
	path, data := unlockFixture(t)
	d, _ := readDocument(data)
	s, _, e := prepareUnlock(d, filepath.Dir(path), "tcp://4.4.4.4:53")
	if e != nil {
		t.Fatal(e)
	}
	m, _ := unlockObject(d.cores[0])
	m["OriginalPath"] = unlockRaw("manual.json")
	d.cores[0] = unlockRaw(m)
	if e = restoreUnlock(d, s); e == nil {
		t.Fatal("conflict overwritten")
	}
}
func TestUnlockMergePreservesUserRules(t *testing.T) {
	m, _ := unlockObject([]byte(`{"dns":{"servers":[{"tag":"old","address":"1.1.1.1"}],"final":"old","rules":[{"domain":["example.com"],"server":"old"}]},"outbounds":[{"type":"direct","tag":"custom-direct"}],"route":{"rules":[{"domain":["keep.example"],"outbound":"custom-direct"}]},"future":123}`))
	b, e := mergeSingUnlock(m, "tcp://4.4.4.4:53")
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"example.com", "keep.example", "custom-direct", "future", "v2bx-unlock-geosite-netflix"} {
		if !bytes.Contains(b, []byte(s)) {
			t.Fatal("lost field", s)
		}
	}
	x, _ := unlockObject([]byte(`{"hosts":{"custom":"1.2.3.4"},"servers":["9.9.9.9"],"queryStrategy":"UseIPv4"}`))
	b, e = mergeXrayUnlock(x, "tcp://4.4.4.4:53")
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"custom", "9.9.9.9", "UseIPv4", "tcp://4.4.4.4:53"} {
		if !bytes.Contains(b, []byte(s)) {
			t.Fatal("lost DNS setting", s)
		}
	}
}

type fakeUnlockService struct {
	active bool
	starts int
	fail   bool
}

func (s *fakeUnlockService) Active() bool { return s.active }
func (s *fakeUnlockService) Stop() error  { s.active = false; return nil }
func (s *fakeUnlockService) Start() error { s.starts++; s.active = true; return nil }
func (s *fakeUnlockService) Healthy() error {
	if s.fail && s.starts == 1 {
		return errors.New("startup failed")
	}
	return nil
}
func TestUnlockTransactionAndDisable(t *testing.T) {
	path, old := unlockFixture(t)
	svc := &fakeUnlockService{active: true}
	var out bytes.Buffer
	validate := func(d *configDocument) error {
		for _, r := range d.cores {
			m, _ := unlockObject(r)
			p := unlockString(m, "OriginalPath")
			if p == "" {
				p = unlockString(m, "DnsConfigPath")
			}
			if _, e := os.Stat(p); e != nil {
				return e
			}
		}
		return nil
	}
	if e := runUnlock(path, "enable", "4.4.4.4", &out, svc, validate); e != nil {
		t.Fatal(e)
	}
	if e := runUnlock(path, "enable", "4.4.4.4", &out, svc, validate); e == nil {
		t.Fatal("duplicate accepted")
	}
	if e := runUnlock(path, "disable", "", &out, svc, validate); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(path)
	a, _ := readDocument(after)
	b, _ := readDocument(old)
	aa, _ := a.marshal()
	bb, _ := b.marshal()
	var got, want any
	json.Unmarshal(aa, &got)
	json.Unmarshal(bb, &want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("restore differs:\n%s\nwant:\n%s", aa, bb)
	}
	if _, e := os.Stat(path + ".dns-unlock.json"); !os.IsNotExist(e) {
		t.Fatal("state not removed")
	}
}
func TestUnlockFailureLeavesOriginal(t *testing.T) {
	for _, stage := range []string{"validation", "startup"} {
		t.Run(stage, func(t *testing.T) {
			path, old := unlockFixture(t)
			svc := &fakeUnlockService{active: true, fail: stage == "startup"}
			var out bytes.Buffer
			e := runUnlock(path, "enable", "4.4.4.4", &out, svc, func(*configDocument) error {
				if stage == "validation" {
					return errors.New("invalid")
				}
				return nil
			})
			if e == nil {
				t.Fatal("failure ignored")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(old, after) {
				t.Fatal("original changed")
			}
			if !svc.active {
				t.Fatal("service not recovered")
			}
			if _, e = os.Stat(path + ".dns-unlock.json"); !os.IsNotExist(e) {
				t.Fatal("failed operation left state")
			}
			dirs, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "dns-unlock-*"))
			if len(dirs) > 0 {
				t.Fatal("failed operation left generated files")
			}
		})
	}
}
func TestUnlockDefaultOffAndTemplates(t *testing.T) {
	b, e := os.ReadFile("../example/sing_origin.json")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(b), "dns_custom") || strings.Contains(string(b), "4.4.4.4") {
		t.Fatal("default enabled")
	}
	for _, b := range [][]byte{singUnlockTemplate, xrayUnlockTemplate} {
		if !json.Valid(b) || !bytes.Contains(b, []byte("4.4.4.4")) {
			t.Fatal("invalid template")
		}
	}
}

func TestUnlockXrayUDPAndNamedCore(t *testing.T) {
	m := map[string]json.RawMessage{}
	b, e := mergeXrayUnlock(m, "udp://4.4.4.4:5353")
	if e != nil {
		t.Fatal(e)
	}
	obj, _ := unlockObject(b)
	a, _ := unlockArray(obj, "servers")
	server, _ := unlockObject(a[0])
	if unlockString(server, "address") != "4.4.4.4" || string(server["port"]) != "5353" {
		t.Fatal("UDP DNS incorrectly mapped")
	}
	path, data := unlockFixture(t)
	data = bytes.ReplaceAll(data, []byte(`,"CoreName":"s"`), nil)
	data = bytes.ReplaceAll(data, []byte(`,"CoreName":"x"`), nil)
	d, _ := readDocument(data)
	if _, _, e = prepareUnlock(d, filepath.Dir(path), "tcp://4.4.4.4:53"); e != nil {
		t.Fatal("unique named core not selected", e)
	}
}
