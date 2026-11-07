package panel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func TestPanelALPN(t *testing.T) {
	var tls TlsSettings
	if e := json.Unmarshal([]byte(`{"alpn":["h3"],"serverName":"example.com"}`), &tls); e != nil {
		t.Fatal(e)
	}
	if len(tls.ALPN) != 1 || tls.ALPN[0] != "h3" || tls.ServerName != "example.com" {
		t.Fatal("ALPN or legacy SNI lost")
	}
	if e := json.Unmarshal([]byte(`{"alpn":123}`), &TlsSettings{}); e == nil {
		t.Fatal("accepted invalid ALPN")
	}
}

func TestPanelALPNPollingUpdate(t *testing.T) {
	protocol := "h3"
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", protocol)
		fmt.Fprintf(w, `{"server_port":443,"tls":1,"network":"xhttp","networkSettings":{"path":"/xhttp","mode":"auto"},"tlsSettings":{"alpn":[%q]},"base_config":{"push_interval":60,"pull_interval":30}}`, protocol)
	})
	for _, value := range []string{"h3", "h2"} {
		protocol = value
		info, e := c.GetNodeInfo()
		if e != nil {
			t.Fatal(e)
		}
		if info == nil || info.VAllss == nil || len(info.VAllss.TlsSettings.ALPN) != 1 || info.VAllss.TlsSettings.ALPN[0] != value {
			t.Fatal("panel ALPN change not returned")
		}
	}
	info, e := c.GetNodeInfo()
	if e != nil || info != nil {
		t.Fatalf("unchanged settings should not trigger reload: %v", e)
	}
}
