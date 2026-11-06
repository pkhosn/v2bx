package sing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/pkhosn/v2bx/core"
	vmessOutbound "github.com/sagernet/sing-box/protocol/vmess"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkhosn/v2bx/api/panel"
	"github.com/pkhosn/v2bx/conf"
	singTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// Exercise the actual TLS options constructed for a VMess WS inbound, then
// assert ECH acceptance on both ends rather than allowing silent fallback.
func TestInboundECHHandshake(t *testing.T) {
	configPEM, keyPEM, err := singTLS.ECHKeygenDefault("public.example")
	if err != nil {
		t.Fatal(err)
	}
	configBlock, _ := pem.Decode([]byte(configPEM))
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if fixture := os.Getenv("V2BX_ECH_PANEL_FIXTURE"); fixture != "" {
		data, e := os.ReadFile(fixture)
		if e != nil {
			t.Fatal(e)
		}
		var settings panel.TlsSettings
		if e = json.Unmarshal(data, &settings); e != nil {
			t.Fatal(e)
		}
		settings.ECH = "custom"
		normalized, e := settings.ECHKeysPEM()
		if e != nil {
			t.Fatal(e)
		}
		keyBlock, _ = pem.Decode([]byte(normalized))
		public, e := base64.StdEncoding.DecodeString(settings.ECHConfig)
		if e != nil {
			t.Fatal(e)
		}
		configBlock = &pem.Block{Type: "ECH CONFIGS", Bytes: public}
		configPEM = string(pem.EncodeToMemory(configBlock))
	}
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"node.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(private)
	roots := x509.NewCertPool()
	cert, _ := x509.ParseCertificate(der)
	roots.AddCert(cert)
	info := &panel.NodeInfo{Type: "vmess", Security: panel.Tls, Common: &panel.CommonNode{ServerPort: 0}, VAllss: &panel.VAllssNode{Network: "ws", TlsSettings: panel.TlsSettings{ECH: "custom", ECHKey: base64.StdEncoding.EncodeToString(keyBlock.Bytes), ECHConfig: base64.StdEncoding.EncodeToString(configBlock.Bytes)}}}
	c := &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions(), CertConfig: &conf.CertConfig{CertMode: "file", CertFile: "unused", KeyFile: "unused"}}
	in, err := getInboundOptions("test", info, c)
	if err != nil {
		t.Fatal(err)
	}
	opts := in.Options.(*option.VMessInboundOptions).TLS
	opts.CertificatePath = ""
	opts.KeyPath = ""
	opts.Certificate = []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	opts.Key = []string{string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))}
	factory := log.NewNOPFactory()
	server, err := singTLS.NewServer(context.Background(), factory.NewLogger("ech-test"), *opts)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	compat := server.(interface{ STDConfig() (*tls.Config, error) })
	serverConfig, err := compat.STDConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		ech, wrong bool
	}{{"ech", true, false}, {"plain", false, false}, {"wrong-key", true, true}} {
		ech := test.ech
		left, right := net.Pipe()
		left.SetDeadline(time.Now().Add(5 * time.Second))
		right.SetDeadline(time.Now().Add(5 * time.Second))
		result := make(chan error, 1)
		go func() {
			s := tls.Server(left, serverConfig)
			err := s.Handshake()
			if err == nil && s.ConnectionState().ECHAccepted != ech {
				err = fmt.Errorf("server ECH acceptance mismatch")
			}
			left.Close()
			result <- err
		}()
		clientConfig := &tls.Config{ServerName: "node.example", RootCAs: roots, MinVersion: tls.VersionTLS13}
		if ech {
			clientConfig.EncryptedClientHelloConfigList = configBlock.Bytes
			if test.wrong {
				different, _, e := singTLS.ECHKeygenDefault("public.example")
				if e != nil {
					t.Fatal(e)
				}
				block, _ := pem.Decode([]byte(different))
				clientConfig.EncryptedClientHelloConfigList = block.Bytes
			}
		}
		client := tls.Client(right, clientConfig)
		err = client.Handshake()
		if test.wrong {
			right.Close()
			<-result
			if err == nil {
				t.Fatal("wrong ECH key silently accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if client.ConnectionState().ECHAccepted != ech {
			t.Fatal("client ECH acceptance mismatch")
		}
		right.Close()
		if err = <-result; err != nil {
			t.Fatal(err)
		}
	}
}

func TestECHVMessWebSocketForward(t *testing.T) {
	configPEM, keyPEM, err := singTLS.ECHKeygenDefault("public.example")
	if err != nil {
		t.Fatal(err)
	}
	configBlock, _ := pem.Decode([]byte(configPEM))
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if fixture := os.Getenv("V2BX_ECH_PANEL_FIXTURE"); fixture != "" {
		data, e := os.ReadFile(fixture)
		if e != nil {
			t.Fatal(e)
		}
		var settings panel.TlsSettings
		if e = json.Unmarshal(data, &settings); e != nil {
			t.Fatal(e)
		}
		settings.ECH = "custom"
		normalized, e := settings.ECHKeysPEM()
		if e != nil {
			t.Fatal(e)
		}
		keyBlock, _ = pem.Decode([]byte(normalized))
		public, e := base64.StdEncoding.DecodeString(settings.ECHConfig)
		if e != nil {
			t.Fatal(e)
		}
		configBlock = &pem.Block{Type: "ECH CONFIGS", Bytes: public}
		configPEM = string(pem.EncodeToMemory(configBlock))
	}
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"node.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(private)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600)
	coreConfig := conf.CoreConfig{Type: "sing", SingConfig: conf.NewSingConfig()}
	generic, err := New(&coreConfig)
	if err != nil {
		t.Fatal(err)
	}
	b := generic.(*Sing)
	defer b.Close()
	if err = b.Start(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	info := &panel.NodeInfo{Type: "vmess", Security: panel.Tls, Common: &panel.CommonNode{ServerPort: port}, VAllss: &panel.VAllssNode{Network: "ws", NetworkSettings: []byte(`{"path":"/test"}`), TlsSettings: panel.TlsSettings{ECH: "custom", ECHKey: base64.StdEncoding.EncodeToString(keyBlock.Bytes), ECHConfig: base64.StdEncoding.EncodeToString(configBlock.Bytes)}}}
	options := &conf.Options{ListenIP: "127.0.0.1", SingOptions: conf.NewSingOptions(), CertConfig: &conf.CertConfig{CertMode: "file", CertFile: certPath, KeyFile: keyPath}}
	if err = b.AddNode("ech-forward", info, options); err != nil {
		t.Fatal(err)
	}
	uuid := "7996103a-d2b8-4097-9dc1-e853fac76d54"
	if _, err = b.AddUsers(&core.AddUsersParams{Tag: "ech-forward", NodeInfo: info, Users: []panel.UserInfo{{Id: 1, Uuid: uuid}}}); err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ech-forward-ok") }))
	defer target.Close()
	factory := log.NewNOPFactory()
	outbound, err := vmessOutbound.NewOutbound(b.ctx, b.router, factory.NewLogger("client"), "client", option.VMessOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(port)}, UUID: uuid, Security: "auto",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: "node.example", Certificate: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, ECH: &option.OutboundECHOptions{Enabled: true, Config: []string{configPEM}}}},
		Transport:                   &option.V2RayTransportOptions{Type: "ws", WebsocketOptions: option.V2RayWebsocketOptions{Path: "/test"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := outbound.(io.Closer); ok {
		defer closer.Close()
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return outbound.DialContext(ctx, network, M.ParseSocksaddr(address))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "ech-forward-ok" {
		t.Fatalf("forward failed: %q %v", body, err)
	}
}

// Optional cross-language fixture generated by the panel's PHP helper.
func TestPanelGeneratedECHFixture(t *testing.T) {
	path := os.Getenv("V2BX_ECH_PANEL_FIXTURE")
	if path == "" {
		t.Skip("set V2BX_ECH_PANEL_FIXTURE to exercise the real panel generator")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings panel.TlsSettings
	if err = json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	settings.ECH = "custom"
	key, err := settings.ECHKeysPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(key, "BEGIN ECH KEYS") {
		t.Fatal("missing key PEM")
	}
}
