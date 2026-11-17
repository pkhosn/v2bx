package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pkhosn/v2bx/api/panel"
	"github.com/pkhosn/v2bx/conf"
	"github.com/pkhosn/v2bx/core"
)

func TestPanelHopRangeAndChoice(t *testing.T) {
	for _, tc := range []struct {
		body, want string
		invalid    bool
	}{
		{`{"mport":"40000-40009"}`, "40000-40009", false},
		{`{"port":"40000-40009"}`, "40000-40009", false},
		{`{"mport":null,"port":40000}`, "", false},
		{`{"port":"40000"}`, "", false},
		{`{}`, "", false},
		{`{"mport":"40000-40001; flush ruleset"}`, "", true},
		{`{"mport":[40000,40009]}`, "", true},
	} {
		var h panel.Hysteria2Node
		if err := json.Unmarshal([]byte(tc.body), &h); err != nil {
			t.Fatal(err)
		}
		got, err := panelHopRange(&panel.NodeInfo{Hysteria2: &h})
		if got != tc.want || (err != nil) != tc.invalid {
			t.Fatalf("%s: %q %v", tc.body, got, err)
		}
	}
	info := &panel.NodeInfo{Hysteria2: &panel.Hysteria2Node{CommonNode: panel.CommonNode{ServerPort: 36005}}}
	for _, tc := range []struct {
		name, input, port string
		want              *nodeHop
	}{
		{"panel default", "\n", `"40000-40009"`, &nodeHop{40000, 40009, 36005}},
		{"panel decline", "n\n", `"40000-40009"`, nil},
		{"manual invalid then valid", "2\nbad\n36000-36009\n40000-40009\n", "", &nodeHop{40000, 40009, 36005}},
		{"off", "\n", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info.Hysteria2.MPort = json.RawMessage(tc.port)
			r := strings.NewReader(tc.input)
			w := &nodeWizard{in: bufio.NewReader(r), input: r, out: &bytes.Buffer{}}
			got, err := w.configureNodeHop(info, nil)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v %v", got, err)
			}
		})
	}
}
func TestMultipleHopRulesAndLegacy(t *testing.T) {
	hops := []nodeHop{{41000, 41009, 36006}, {40000, 40009, 36005}}
	rules, err := renderNodeHops(hops)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseNodeHops([]byte(rules))
	if err != nil || len(got) != 2 || got[0] != hops[1] {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	legacy, _ := hopNft(40000, 40009, 36005, "ipv4")
	if got, err = parseNodeHops([]byte(legacy)); err != nil || len(got) != 1 {
		t.Fatal(err)
	}
	for _, bad := range []string{rules + "flush ruleset\n", strings.Replace(rules, "fib daddr type local ", "", 1), ""} {
		if _, err = parseNodeHops([]byte(bad)); err == nil {
			t.Fatal("foreign rule accepted")
		}
	}
	for _, bad := range [][]nodeHop{{{40000, 40009, 443}, {40005, 40015, 8443}}, {{40000, 40009, 443}, {41000, 41009, 40005}}} {
		if _, err = renderNodeHops(bad); err == nil {
			t.Fatal("overlap accepted")
		}
	}
}

type fakeHopSystem struct {
	m               *hopManager
	table           []byte
	enabled, active bool
	fail            string
	calls           []string
}

func (f *fakeHopSystem) run(input, name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	if strings.Contains(input, "flush ruleset") {
		return nil, fmt.Errorf("host flush forbidden")
	}
	if cmd == f.fail {
		f.fail = ""
		return nil, fmt.Errorf("injected failure")
	}
	switch cmd {
	case "nft list tables":
		if f.table != nil {
			return []byte("table inet " + hopTable + "\n"), nil
		}
		return nil, nil
	case "nft list table inet " + hopTable:
		if f.table == nil {
			return nil, fmt.Errorf("missing table")
		}
		return f.table, nil
	case "nft -c -f -":
		return nil, nil
	case "nft -f -":
		input = strings.TrimPrefix(input, "delete table inet "+hopTable+"\n")
		f.table = []byte(input)
		if input == "" {
			f.table = nil
		}
		return nil, nil
	case "nft delete table inet " + hopTable:
		f.table = nil
		return nil, nil
	case "systemctl is-enabled " + hopUnit:
		if !f.enabled {
			return []byte("disabled"), fmt.Errorf("disabled")
		}
		return []byte("enabled"), nil
	case "systemctl is-active " + hopUnit:
		if !f.active {
			return []byte("inactive"), fmt.Errorf("inactive")
		}
		return []byte("active"), nil
	case "systemctl disable --now " + hopUnit:
		f.enabled = false
		f.active = false
		f.table = nil
		return nil, nil
	case "systemctl enable " + hopUnit:
		f.enabled = true
		return nil, nil
	case "systemctl start " + hopUnit, "systemctl restart " + hopUnit:
		b, e := os.ReadFile(f.m.rules)
		if e != nil {
			return nil, e
		}
		f.table = b
		f.active = true
		return nil, nil
	case "systemctl daemon-reload":
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected command %s", cmd)
}
func fakeHopManager(t *testing.T) (*hopManager, *fakeHopSystem) {
	t.Helper()
	dir := t.TempDir()
	m := &hopManager{rules: filepath.Join(dir, "rules.nft"), service: filepath.Join(dir, "hop.service"), lock: filepath.Join(dir, "lock"), nft: "nft"}
	f := &fakeHopSystem{m: m}
	m.run = f.run
	return m, f
}
func freeTestHop(t *testing.T, target int) nodeHop {
	t.Helper()
	l, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	return nodeHop{port, port, target}
}
func TestHopTransactionRollbackAndCommit(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		existing, commit, applyFail bool
	}{
		{"new commit", false, true, false}, {"new config save failure", false, false, false},
		{"legacy migrate", true, true, false}, {"legacy config save failure", true, false, false},
		{"legacy restart failure", true, false, true}, {"new restart failure", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, f := fakeHopManager(t)
			var oldRules, oldUnit []byte
			old := freeTestHop(t, 443)
			next := freeTestHop(t, 8443)
			if tc.existing {
				s, _ := hopNft(old.Start, old.End, old.Target, "ipv4")
				oldRules = []byte(s)
				oldUnit = []byte(hopUnitText("nft"))
				os.WriteFile(m.rules, oldRules, 0600)
				os.WriteFile(m.service, oldUnit, 0644)
				f.table = oldRules
				f.enabled = true
				f.active = true
			}
			if tc.applyFail {
				f.fail = "systemctl restart " + hopUnit
			}
			finish, err := m.begin([]nodeHop{next}, map[int]bool{443: true, 8443: true}, false)
			if tc.applyFail {
				if err == nil {
					t.Fatal("failure hidden")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err = finish(tc.commit); err != nil {
					t.Fatal(err)
				}
			}
			if tc.commit {
				got, e := parseNodeHops(f.table)
				if e != nil || len(got) != 1 || got[0] != next || !f.active || !f.enabled {
					t.Fatalf("bad commit: %+v %v", got, e)
				}
			} else {
				got, _ := hopFile(m.rules)
				unit, _ := hopFile(m.service)
				if !bytes.Equal(got, oldRules) || !bytes.Equal(unit, oldUnit) || !bytes.Equal(f.table, oldRules) || f.enabled != tc.existing || f.active != tc.existing {
					t.Fatal("rollback failed to restore original state")
				}
			}
			// Verify the transaction released its lock after either success or failure.
			finish, err = m.begin(nil, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			if err = finish(true); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestHopDisableAndPreserveOtherNodes(t *testing.T) {
	m, f := fakeHopManager(t)
	a := freeTestHop(t, 443)
	b := freeTestHop(t, 8443)
	rules, err := renderNodeHops([]nodeHop{a, b})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(m.rules, []byte(rules), 0600)
	os.WriteFile(m.service, []byte(hopUnitText("nft")), 0644)
	f.table = []byte(rules)
	f.active = true
	f.enabled = true
	finish, err := m.begin(nil, map[int]bool{443: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = finish(true); err != nil {
		t.Fatal(err)
	}
	got, err := parseNodeHops(f.table)
	if err != nil || len(got) != 1 || got[0] != b {
		t.Fatal("other node lost", err)
	}
	finish, err = m.begin(nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = finish(true); err != nil {
		t.Fatal(err)
	}
	if f.table != nil || f.active || f.enabled {
		t.Fatal("replace retained obsolete mappings")
	}
	if b, err := hopFile(m.rules); err != nil || b != nil {
		t.Fatal("obsolete rule file retained")
	}
}
func TestHopRejectForeignState(t *testing.T) {
	m, f := fakeHopManager(t)
	f.table = []byte("foreign")
	if _, err := m.begin([]nodeHop{freeTestHop(t, 443)}, nil, false); err == nil {
		t.Fatal("foreign table overwritten")
	}
	if string(f.table) != "foreign" {
		t.Fatal("foreign table changed")
	}
}

func TestWizardIntegratedHY2(t *testing.T) {
	if !strings.Contains("|"+strings.Join(core.RegisteredCore(), "|")+"|", "|hysteria2|") {
		t.Skip("requires hy2 core")
	}
	for _, mode := range []string{"new", "edit", "disable", "cancel", "concurrent save", "retry apply", "apply failure cancel"} {
		t.Run(mode, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.json")
			original := []byte(`{"Cores":[{"Type":"hysteria2","Name":"original"}],"Nodes":[{"ApiHost":"https://panel.example","ApiKey":"secret","NodeType":"hysteria2","NodeID":1,"Core":"hysteria2","CoreName":"original","Custom":true,"CertConfig":{"CertMode":"none"},"PortHop":{"Start":41000,"End":41009,"Target":36005}}],"Future":true}`)
			os.WriteFile(p, original, 0600)
			id := "2"
			confirm := ""
			choice := "\n"
			if mode != "new" {
				id = "1"
				confirm = "y\n"
			}
			if mode == "disable" {
				choice = "n\n"
			}
			if mode == "cancel" {
				choice = ""
			}
			retry := ""
			if mode == "retry apply" {
				retry = "1\n"
			}
			if mode == "apply failure cancel" {
				retry = "0\n"
			}
			r := strings.NewReader("https://panel.example\n\nn\n3\n" + id + "\n" + confirm + choice + "n\n" + retry)
			applied, finished, certificate := 0, false, 0
			w := &nodeWizard{input: r, in: bufio.NewReader(r), out: &bytes.Buffer{}, fetch: func(*conf.ApiConfig) (*panel.NodeInfo, error) {
				target := 36005
				if mode == "new" {
					target = 36006
				}
				return &panel.NodeInfo{Security: panel.None, Hysteria2: &panel.Hysteria2Node{CommonNode: panel.CommonNode{ServerPort: target}, MPort: json.RawMessage(`"40000-40009"`)}}, nil
			}, ensure: func(*conf.CertConfig) error { certificate++; return nil }, applyHops: func(h []nodeHop, touched map[int]bool, replace bool) (func(bool) error, error) {
				applied++
				if (mode == "retry apply" || mode == "apply failure cancel") && applied == 1 {
					return nil, fmt.Errorf("temporary nft error")
				}
				if replace {
					t.Fatal("unexpected replacement")
				}
				if mode == "disable" && len(h) != 0 {
					t.Fatal("disabled mapping retained")
				}
				if mode == "new" && len(h) != 2 {
					t.Fatal("existing mapping lost")
				}
				if mode == "concurrent save" {
					os.WriteFile(p, []byte("concurrent"), 0600)
				}
				return func(ok bool) error {
					finished = true
					if ok != (mode != "concurrent save") {
						t.Fatal("incorrect rollback decision")
					}
					return nil
				}, nil
			}}
			err := w.run(p, false)
			if mode == "cancel" {
				if err == nil || applied != 0 {
					t.Fatal("cancel applied mappings")
				}
				return
			}
			if mode == "apply failure cancel" {
				current, _ := os.ReadFile(p)
				if err == nil || applied != 1 || finished || !bytes.Equal(current, original) {
					t.Fatal("failed apply saved configuration")
				}
				return
			}
			wantApplied := 1
			if mode == "retry apply" {
				wantApplied = 2
			}
			if applied != wantApplied || !finished {
				t.Fatal("mappings not transacted")
			}
			if mode == "concurrent save" {
				if err == nil {
					t.Fatal("concurrent write ignored")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(p)
			d, err := readDocument(data)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "new" {
				if certificate != 1 || len(d.nodes) != 2 {
					t.Fatal("new node failed")
				}
			} else {
				var saved map[string]json.RawMessage
				if err = json.Unmarshal(d.nodes[0], &saved); err != nil {
					t.Fatal(err)
				}
				if certificate != 0 || len(d.nodes) != 1 || string(saved["Custom"]) != "true" || d.parsed[0].Options.CoreName != "original" || d.parsed[0].Options.CertConfig.CertMode != "none" {
					t.Fatal("edit rebuilt existing node")
				}
			}
		})
	}
}

// Exercise Linux's real prerouting redirect in private network namespaces.
// No interfaces, routes or firewall tables are created in the host namespace.
func TestHopKernelRedirection(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for private network namespaces")
	}
	for _, tool := range []string{"unshare", "nsenter", "ip", "nft", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("missing " + tool)
		}
	}
	if err := exec.Command("unshare", "-n", "true").Run(); err != nil {
		t.Skip("network namespaces unavailable")
	}
	rules, err := renderNodeHops([]nodeHop{{40000, 40001, 36005}, {41000, 41001, 36006}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	script := `
import os,subprocess,socket,time

def run(args, data=None):
 return subprocess.run(args,input=data,text=True,check=True,capture_output=True).stdout

peer=subprocess.Popen(['unshare','-n','sleep','60'])
server=None
try:
 time.sleep(0.1)
 run(['ip','link','add','hy-client','type','veth','peer','name','hy-server'])
 run(['ip','addr','add','10.203.0.1/24','dev','hy-client'])
 run(['ip','link','set','hy-client','up'])
 run(['ip','link','set','hy-server','netns',str(peer.pid)])
 prefix=['nsenter','-t',str(peer.pid),'-n']
 run(prefix+['ip','addr','add','10.203.0.2/24','dev','hy-server'])
 run(prefix+['ip','link','set','hy-server','up'])
 rules=os.environ['V2BX_HOP_TEST_RULES']
 run(prefix+['nft','-c','-f','-'],rules)
 run(prefix+['nft','-f','-'],rules)
 server_code="""
import socket,select
sockets=[]
for port in [36005,36006]:
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',port));sockets.append(s)
print('ready',flush=True)
while True:
 for s in select.select(sockets,[],[],10)[0]:
  data,addr=s.recvfrom(1024);s.sendto(str(s.getsockname()[1]).encode()+b':'+data,addr)
"""
 server=subprocess.Popen(prefix+['python3','-u','-c',server_code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 assert server.stdout.readline().strip()=='ready'
 def verify():
  for port,target in [(36005,36005),(40000,36005),(40001,36005),(41000,36006),(41001,36006)]:
   s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3)
   s.sendto(b'probe',('10.203.0.2',port));data,addr=s.recvfrom(1024)
   assert data==str(target).encode()+b':probe' and addr[1]==port,(port,data,addr)
   s.close()
 verify()
 # Reapply the boot-time rules and prove both original and hopping ports work.
 run(prefix+['nft','delete','table','inet','v2bx_hy_hop'])
 run(prefix+['nft','-f','-'],rules)
 verify()
 output=run(prefix+['nft','list','table','inet','v2bx_hy_hop'])
 assert 'counter packets 0 ' not in output,output
 print('Two HY2 targets, four hopping ports and rule restoration verified')
finally:
 if server is not None:
  server.terminate();server.wait(timeout=3)
 peer.terminate();peer.wait(timeout=3)
`
	c := exec.CommandContext(ctx, "unshare", "-n", "python3", "-c", script)
	c.Env = append(os.Environ(), "V2BX_HOP_TEST_RULES="+rules)
	output, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("kernel redirect: %v\n%s", err, output)
	}
	t.Log(string(output))
}

func TestInactiveHopServiceRollback(t *testing.T) {
	m, f := fakeHopManager(t)
	old := freeTestHop(t, 443)
	next := freeTestHop(t, 8443)
	rules, _ := renderNodeHops([]nodeHop{old})
	unit := hopUnitText("nft")
	os.WriteFile(m.rules, []byte(rules), 0600)
	os.WriteFile(m.service, []byte(unit), 0644)
	finish, err := m.begin([]nodeHop{next}, map[int]bool{443: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = finish(false); err != nil {
		t.Fatal(err)
	}
	restored, _ := os.ReadFile(m.rules)
	if f.active || f.enabled || f.table != nil || string(restored) != rules {
		t.Fatal("inactive state was not restored")
	}
}
