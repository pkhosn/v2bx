package cmd

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkhosn/v2bx/api/panel"
	"github.com/pkhosn/v2bx/conf"
)

func TestTunnelTokenAndUnit(t *testing.T) {
	token := base64.StdEncoding.EncodeToString([]byte(`{"a":"test-account","t":"test-id","s":"test-secret"}`))
	if e := validateTunnelToken(token); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"", token + "\n", strings.Repeat("a", 17000), base64.StdEncoding.EncodeToString([]byte(`{"a":"test-account"}`))} {
		if e := validateTunnelToken(bad); e == nil {
			t.Fatal("accepted invalid token")
		} else if bad != "" && strings.Contains(e.Error(), bad) {
			t.Fatal("token leaked")
		}
	}
	for _, protocol := range []string{"auto", "http2", "quic"} {
		unit, e := tunnelUnitText("/usr/bin/cloudflared", protocol)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(unit, token) || !strings.Contains(unit, "--token-file "+tunnelToken) || !strings.Contains(unit, "--protocol "+protocol) {
			t.Fatal("unsafe unit")
		}
	}
	for _, binary := range []string{"relative", "/tmp/with space", "/tmp/%n", "/tmp/evil\nExecStart=bad", "/tmp/quote\""} {
		if _, e := tunnelUnitText(binary, "auto"); e == nil {
			t.Fatal("accepted unsafe path")
		}
	}
	if _, e := tunnelUnitText("/usr/bin/cloudflared", "bad"); e == nil {
		t.Fatal("accepted protocol")
	}
}

func TestTunnelOriginValidation(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	path := filepath.Join(t.TempDir(), "config.json")
	write := func(ip, core string) {
		t.Helper()
		e := os.WriteFile(path, []byte(fmt.Sprintf(`{"Cores":[{"Type":"xray"}],"Nodes":[{"ApiHost":"https://example.invalid","ApiKey":"dummy","NodeID":1,"NodeType":"vless","Core":%q,"ListenIP":%q}]}`, core, ip)), 0600)
		if e != nil {
			t.Fatal(e)
		}
	}
	info := &panel.NodeInfo{Type: "vless", Common: &panel.CommonNode{ServerPort: port}, VAllss: &panel.VAllssNode{Network: "xhttp"}}
	fetch := func(*conf.ApiConfig) (*panel.NodeInfo, error) { return info, nil }
	write("127.0.0.1", "xray")
	if got, e := checkTunnelNode(path, 1, fetch); e != nil || got != port {
		t.Fatalf("origin: %d %v", got, e)
	}
	info.Security = panel.Tls
	if _, e := checkTunnelNode(path, 1, fetch); e == nil {
		t.Fatal("accepted TLS origin")
	}
	info.Security = panel.None
	info.Common = nil
	if _, e := checkTunnelNode(path, 1, fetch); e == nil {
		t.Fatal("accepted missing common")
	}
	info.Common = &panel.CommonNode{ServerPort: port}
	for _, ip := range []string{"0.0.0.0", "192.0.2.1"} {
		write(ip, "xray")
		if _, e := checkTunnelNode(path, 1, fetch); e == nil {
			t.Fatal("accepted public origin")
		}
	}
	write("127.0.0.1", "sing")
	if _, e := checkTunnelNode(path, 1, fetch); e == nil {
		t.Fatal("accepted sing")
	}
}

func TestTunnelLifecycle(t *testing.T) {
	token := base64.StdEncoding.EncodeToString([]byte(`{"a":"test-account","t":"test-id","s":"test-secret"}`))
	for _, failStart := range []bool{false, true} {
		t.Run(fmt.Sprint(failStart), func(t *testing.T) {
			dir := t.TempDir()
			unit := filepath.Join(dir, "managed.service")
			secret := filepath.Join(dir, "token")
			calls := []string{}
			runner := func(_ string, name string, args ...string) ([]byte, error) {
				call := name + " " + strings.Join(args, " ")
				calls = append(calls, call)
				if strings.Contains(call, token) {
					t.Fatal("secret in arguments")
				}
				if name == "/usr/bin/cloudflared" {
					return []byte("--token-file"), nil
				}
				if failStart && strings.Contains(call, "enable --now") {
					return nil, fmt.Errorf("simulated systemctl failure")
				}
				return nil, nil
			}
			e := enableTunnelFiles("/usr/bin/cloudflared", "auto", token, unit, secret, runner)
			if failStart {
				if e == nil {
					t.Fatal("failure lost")
				}
				for _, p := range []string{unit, secret} {
					if _, e = os.Stat(p); !os.IsNotExist(e) {
						t.Fatal("failed start left file")
					}
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			stat, e := os.Stat(secret)
			if e != nil || stat.Mode().Perm() != 0600 {
				t.Fatal("token permissions", e)
			}
			if e = enableTunnelFiles("/usr/bin/cloudflared", "auto", token, unit, secret, runner); e == nil {
				t.Fatal("overwrote managed files")
			}
			if e = disableTunnelFiles(unit, secret, runner); e != nil {
				t.Fatal(e)
			}
			for _, p := range []string{unit, secret} {
				if _, e = os.Stat(p); !os.IsNotExist(e) {
					t.Fatal("disable left file")
				}
			}
			for _, call := range calls {
				if strings.Contains(call, "systemctl") && !strings.Contains(call, "daemon-reload") && !strings.HasSuffix(call, tunnelUnit) {
					t.Fatal("touched another service", call)
				}
			}
			if e = os.WriteFile(unit, []byte("Description=another service\n"), 0644); e != nil {
				t.Fatal(e)
			}
			if e = disableTunnelFiles(unit, secret, runner); e == nil {
				t.Fatal("removed unowned unit")
			}
		})
	}
}
