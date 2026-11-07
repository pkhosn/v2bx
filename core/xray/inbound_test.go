package xray

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pkhosn/v2bx/api/panel"
	"github.com/pkhosn/v2bx/conf"
	"github.com/quic-go/quic-go/http3"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	xconf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vless"
	vin "github.com/xtls/xray-core/proxy/vless/inbound"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func h3Fixture(t *testing.T) (*conf.Options, *panel.NodeInfo, *x509.CertPool) {
	t.Helper()
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer fixture.Close()
	cert := fixture.TLS.Certificates[0]
	key, e := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if e = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	o := &conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions(), CertConfig: &conf.CertConfig{CertMode: "file", CertFile: certPath, KeyFile: keyPath}}
	n := &panel.NodeInfo{Type: "vless", Security: panel.Tls, Common: &panel.CommonNode{ServerPort: 443}, VAllss: &panel.VAllssNode{Network: "xhttp", NetworkSettings: json.RawMessage(`{"path":"/test-xhttp","mode":"auto"}`)}}
	return o, n, roots
}
func inboundALPN(t *testing.T, o *conf.Options, n *panel.NodeInfo) []string {
	t.Helper()
	in, e := buildInbound(o, n, "test-h3")
	if e != nil {
		t.Fatal(e)
	}
	v, e := in.ReceiverSettings.GetInstance()
	if e != nil {
		t.Fatal(e)
	}
	for _, security := range v.(*proxyman.ReceiverConfig).StreamSettings.SecuritySettings {
		c, e := security.GetInstance()
		if e != nil {
			t.Fatal(e)
		}
		if tlsConfig, ok := c.(*xtls.Config); ok {
			return tlsConfig.NextProtocol
		}
	}
	t.Fatal("TLS missing")
	return nil
}
func TestInboundALPN(t *testing.T) {
	o, n, _ := h3Fixture(t)
	if protocols := inboundALPN(t, o, n); len(protocols) != 0 {
		t.Fatalf("default changed: %v", protocols)
	}
	n.VAllss.TlsSettings.ALPN = []string{"h3"}
	if got := inboundALPN(t, o, n); len(got) != 1 || got[0] != "h3" {
		t.Fatal(got)
	}
	o.XrayOptions.TLSALPN = []string{"http/1.1"}
	if got := inboundALPN(t, o, n); len(got) != 1 || got[0] != "h3" {
		t.Fatal("local option overrode panel", got)
	}
	n.VAllss.TlsSettings.ALPN = []string{"h2"}
	if got := inboundALPN(t, o, n); len(got) != 1 || got[0] != "h2" {
		t.Fatal("panel update ignored", got)
	}
	n.VAllss.TlsSettings.ALPN = []string{}
	if got := inboundALPN(t, o, n); len(got) != 0 {
		t.Fatal("explicit empty panel ALPN ignored", got)
	}
	n.VAllss.TlsSettings.ALPN = nil
	if got := inboundALPN(t, o, n); len(got) != 1 || got[0] != "http/1.1" {
		t.Fatal("legacy local fallback lost", got)
	}
	o.XrayOptions.TLSALPN = []string{"h3", "h2"}
	if _, e := buildInbound(o, n, "bad"); e == nil {
		t.Fatal("accepted mixed H3")
	}
	o.XrayOptions.TLSALPN = []string{"h3"}
	n.Security = panel.None
	if _, e := buildInbound(o, n, "bad"); e == nil {
		t.Fatal("accepted plaintext H3")
	}
	n.Security = panel.Tls
	n.VAllss.Network = "ws"
	n.VAllss.NetworkSettings = json.RawMessage(`{}`)
	if _, e := buildInbound(o, n, "bad"); e == nil {
		t.Fatal("accepted WS H3")
	}
}
func TestXHTTPRealH3(t *testing.T) {
	o, n, roots := h3Fixture(t)
	o.XrayOptions.TLSALPN = []string{"h3"}
	l, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	n.Common.ServerPort = l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	in, e := buildInbound(o, n, "test-h3")
	if e != nil {
		t.Fatal(e)
	}
	settings, e := in.ProxySettings.GetInstance()
	if e != nil {
		t.Fatal(e)
	}
	settings.(*vin.Config).Clients = []*protocol.User{{Email: "local-test", Account: serial.ToTypedMessage(&vless.Account{Id: "11111111-1111-4111-8111-111111111111"})}}
	in.ProxySettings = serial.ToTypedMessage(settings)
	var base xconf.Config
	if e = json.Unmarshal([]byte(`{"outbounds":[{"protocol":"freedom"}]}`), &base); e != nil {
		t.Fatal(e)
	}
	cfg, e := base.Build()
	if e != nil {
		t.Fatal(e)
	}
	cfg.Inbound = []*core.InboundHandlerConfig{in}
	server, e := core.New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	if e = server.Start(); e != nil {
		t.Fatal(e)
	}
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "GET", "https://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(n.Common.ServerPort))+"/other", nil)
	if e != nil {
		t.Fatal(e)
	}
	response, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	io.Copy(io.Discard, response.Body)
	if response.ProtoMajor != 3 || response.StatusCode != 404 {
		t.Fatalf("expected real H3 path rejection: %s %d", response.Proto, response.StatusCode)
	}
	// Exercise an authenticated VLESS request over XHTTP/H3 with certificate verification.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "h3-proxy-ok") }))
	defer target.Close()
	raw := []byte(fmt.Sprintf(`{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":"11111111-1111-4111-8111-111111111111","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","security":"tls","xhttpSettings":{"path":"/test-xhttp","mode":"packet-up"},"tlsSettings":{"serverName":"example.com","alpn":["h3"],"disableSystemRoot":true,"certificates":[{"usage":"verify","certificateFile":%q}]}}}]}`, n.Common.ServerPort, o.CertConfig.CertFile))
	if e != nil {
		t.Fatal(e)
	}
	var clientConf xconf.Config
	if e = json.Unmarshal(raw, &clientConf); e != nil {
		t.Fatal(e)
	}
	clientBuilt, e := clientConf.Build()
	if e != nil {
		t.Fatal(e)
	}
	proxyClient, e := core.New(clientBuilt)
	if e != nil {
		t.Fatal(e)
	}
	defer proxyClient.Close()
	if e = proxyClient.Start(); e != nil {
		t.Fatal(e)
	}
	proxyTransport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		dest, e := xnet.ParseDestination("tcp:" + address)
		if e != nil {
			return nil, e
		}
		return core.Dial(ctx, proxyClient, dest)
	}}
	defer proxyTransport.CloseIdleConnections()
	proxyHTTP := &http.Client{Transport: proxyTransport, Timeout: 8 * time.Second}
	r, e := proxyHTTP.Get(target.URL)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	body, e := io.ReadAll(r.Body)
	if e != nil || string(body) != "h3-proxy-ok" {
		t.Fatalf("proxy response: %q %v", body, e)
	}

}

func TestPanelALPNReloadTCPListener(t *testing.T) {
	o, n, roots := h3Fixture(t)
	// A stale local H3 option must not override subsequent panel choices.
	o.XrayOptions.TLSALPN = []string{"h3"}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	n.Common.ServerPort = l.Addr().(*net.TCPAddr).Port
	l.Close()
	cfg, e := (&xconf.Config{}).Build()
	if e != nil {
		t.Fatal(e)
	}
	server, e := core.New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	if e = server.Start(); e != nil {
		t.Fatal(e)
	}
	manager := server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	for i, protocol := range []string{"h2", "http/1.1", "h2"} {
		if i > 0 {
			if e = manager.RemoveHandler(context.Background(), "panel-reload"); e != nil {
				t.Fatal(e)
			}
		}
		n.VAllss.TlsSettings.ALPN = []string{protocol}
		in, e := buildInbound(o, n, "panel-reload")
		if e != nil {
			t.Fatal(e)
		}
		raw, e := core.CreateObject(server, in)
		if e != nil {
			t.Fatal(e)
		}
		if e = manager.AddHandler(context.Background(), raw.(inbound.Handler)); e != nil {
			t.Fatal(e)
		}
		conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(n.Common.ServerPort)), &tls.Config{RootCAs: roots, NextProtos: []string{protocol}})
		if e != nil {
			t.Fatal(e)
		}
		got := conn.ConnectionState().NegotiatedProtocol
		conn.Close()
		if got != protocol {
			t.Fatalf("negotiated %q, want panel value %q", got, protocol)
		}
	}
}
