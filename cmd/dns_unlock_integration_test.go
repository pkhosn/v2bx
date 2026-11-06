//go:build sing && xray

package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pkhosn/v2bx/conf"
	singCore "github.com/pkhosn/v2bx/core/sing"
	xcore "github.com/xtls/xray-core/core"
	xconf "github.com/xtls/xray-core/infra/conf"
	"golang.org/x/net/proxy"
)

func localUnlockDNS(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	count := &atomic.Int32{}
	server := &dns.Server{Listener: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			if q.Qtype == dns.TypeA {
				count.Add(1)
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(127, 0, 0, 1)})
			}
		}
		_ = w.WriteMsg(m)
	})}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })
	return "tcp://" + listener.Addr().String(), count
}
func localUnlockPort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
func requestUnlockProxy(t *testing.T, port int, target string) {
	t.Helper()
	dialer, e := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil, &net.Dialer{Timeout: 3 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	r, e := client.Get(target)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	if string(b) != "unlock-ok" {
		t.Fatal("proxy response mismatch", string(b))
	}
}

func TestUnlockRealSingDNSAndProxy(t *testing.T) {
	unlock, unlockCount := localUnlockDNS(t)
	ordinary, ordinaryCount := localUnlockDNS(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "unlock-ok") }))
	defer target.Close()
	_, targetPort, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	original := map[string]json.RawMessage{"dns": unlockRaw(map[string]any{"servers": []any{map[string]any{"tag": "public", "address": ordinary}}, "final": "public"}), "outbounds": unlockRaw([]any{map[string]any{"tag": "direct", "type": "direct", "domain_resolver": map[string]any{"server": "public"}}})}
	data, e := mergeSingUnlock(original, unlock)
	if e != nil {
		t.Fatal(e)
	}
	m, _ := unlockObject(data)
	route, _ := unlockSection(m, "route")
	// Replace downloaded rule sets with equivalent local fixtures. This checks
	// merged DNS/resolve behavior without external network or service accounts.
	var sets []map[string]any
	json.Unmarshal(route["rule_set"], &sets)
	for _, s := range sets {
		delete(s, "url")
		delete(s, "download_detour")
		delete(s, "format")
		s["type"] = "inline"
		s["rules"] = []any{map[string]any{"domain_suffix": []string{"stream.test"}}}
	}
	route["rule_set"] = unlockRaw(sets)
	m["route"] = unlockRaw(route)
	port := localUnlockPort(t)
	m["inbounds"] = unlockRaw([]any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": port}})
	file := filepath.Join(t.TempDir(), "origin.json")
	os.WriteFile(file, unlockRaw(m), 0600)
	doc := &configDocument{cores: []json.RawMessage{unlockRaw(map[string]any{"Type": "sing", "OriginalPath": file})}}
	if e = validateUnlockFiles(doc); e != nil {
		t.Fatal("candidate validation failed", e)
	}
	cfg := conf.NewSingConfig()
	cfg.OriginalPath = file
	cfg.LogConfig.Level = "error"
	instance, e := singCore.New(&conf.CoreConfig{Type: "sing", SingConfig: cfg})
	if e != nil {
		t.Fatal(e)
	}
	defer instance.Close()
	if e = instance.Start(); e != nil {
		t.Fatal(e)
	}
	requestUnlockProxy(t, port, "http://chatgpt.com:"+targetPort)
	if unlockCount.Load() == 0 {
		t.Fatal("unlock DNS was bypassed")
	}
	before := unlockCount.Load()
	requestUnlockProxy(t, port, "http://ordinary.test:"+targetPort)
	if ordinaryCount.Load() == 0 || unlockCount.Load() != before {
		t.Fatal("ordinary domain did not use original DNS")
	}
	requestUnlockProxy(t, port, "http://stream.test:"+targetPort)
	if unlockCount.Load() <= before {
		t.Fatal("rule set did not use unlock DNS")
	}
}

func TestUnlockRealXrayDNSAndProxy(t *testing.T) {
	unlock, count := localUnlockDNS(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "unlock-ok") }))
	defer target.Close()
	_, targetPort, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	data, e := mergeXrayUnlock(map[string]json.RawMessage{}, unlock)
	if e != nil {
		t.Fatal(e)
	}
	// The production templates use the installed geosite database. This fixture
	// substitutes explicit domains to keep the test fully local and portable.
	dnsConfig, _ := unlockObject(data)
	servers, _ := unlockArray(dnsConfig, "servers")
	custom, _ := unlockObject(servers[0])
	custom["domains"] = unlockRaw([]string{"domain:chatgpt.com"})
	dnsConfig["servers"] = unlockRaw([]any{custom})
	port := localUnlockPort(t)
	raw := unlockRaw(map[string]any{"log": map[string]any{"loglevel": "error"}, "dns": dnsConfig, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "sendThrough": "0.0.0.0", "settings": map[string]any{"domainStrategy": "UseIP"}}}})
	var cfg xconf.Config
	if e = json.Unmarshal(raw, &cfg); e != nil {
		t.Fatal(e)
	}
	built, e := cfg.Build()
	if e != nil {
		t.Fatal(e)
	}
	instance, e := xcore.New(built)
	if e != nil {
		t.Fatal(e)
	}
	defer instance.Close()
	if e = instance.Start(); e != nil {
		t.Fatal(e)
	}
	requestUnlockProxy(t, port, "http://chatgpt.com:"+targetPort)
	if count.Load() == 0 {
		t.Fatal("Xray bypassed unlock DNS")
	}
}
