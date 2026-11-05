package panel

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pkhosn/v2bx/conf"
)

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("simulated connection failure")
}

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	c, err := New(&conf.ApiConfig{
		APIHost:  server.URL,
		Key:      "token",
		NodeType: "V2ray",
		NodeID:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.client.SetRetryCount(0)
	return c
}

func TestClient_GetNodeInfoErrors(t *testing.T) {
	for _, scenario := range []string{"transport", "http", "decode"} {
		t.Run(scenario, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", "failed")
				if scenario == "http" {
					w.WriteHeader(http.StatusInternalServerError)
				}
				_, _ = w.Write([]byte(`{"server_port":"invalid"}`))
			})
			if scenario == "transport" {
				c.client.SetTransport(failingTransport{})
			}
			for attempt := 1; attempt <= 2; attempt++ {
				node, err := c.GetNodeInfo()
				if err == nil || node != nil {
					t.Errorf("attempt %d: node=%v, err=%v; want error", attempt, node, err)
				}
				if c.nodeEtag != "" || c.responseBodyHash != "" {
					t.Errorf("failed request changed cache: ETag=%q, hash=%q", c.nodeEtag, c.responseBodyHash)
				}
			}
		})
	}
}

func TestClient_GetNodeInfoCache(t *testing.T) {
	const body = `{"server_port":443,"network":"tcp","base_config":{"push_interval":60,"pull_interval":30}}`
	request := 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		request++
		wantETag := ""
		if request == 2 {
			wantETag = "first"
		} else if request > 2 {
			wantETag = "second"
		}
		if got := r.Header.Get("If-None-Match"); got != wantETag {
			t.Errorf("request %d: ETag=%q, want %q", request, got, wantETag)
		}
		switch request {
		case 1:
			w.Header().Set("ETag", "first")
		case 2:
			w.Header().Set("ETag", "second")
		case 3:
			w.WriteHeader(http.StatusNotModified)
			return
		case 4:
			w.Header().Set("ETag", "failed")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"unavailable"}`))
			return
		default:
			w.Header().Set("ETag", "second")
		}
		_, _ = w.Write([]byte(body))
	})
	node, err := c.GetNodeInfo()
	if err != nil || node == nil {
		t.Fatalf("initial config: node=%v, err=%v", node, err)
	}
	if node.Common.ServerPort != 443 || node.Id != 1 || node.Type != "vmess" {
		t.Fatalf("unexpected config: %+v", node)
	}
	hash := c.responseBodyHash
	for attempt := 2; attempt <= 5; attempt++ {
		node, err = c.GetNodeInfo()
		if (attempt == 4) != (err != nil) || node != nil {
			t.Errorf("request %d: node=%v, err=%v", attempt, node, err)
		}
		if c.nodeEtag != "second" || c.responseBodyHash != hash {
			t.Errorf("request %d: unexpected cache: ETag=%q, hash=%q", attempt, c.nodeEtag, c.responseBodyHash)
		}
	}
}

func TestClient_ReportUserTraffic(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/server/UniProxy/push" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		_, _ = w.Write([]byte(`{}`))
	})
	if err := c.ReportUserTraffic([]UserTraffic{
		{
			UID:      10372,
			Upload:   1000,
			Download: 1000,
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestClientRejectsMissingBaseConfig(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"server_port":443,"network":"tcp"}`)) })
	if info, err := c.GetNodeInfo(); err == nil || info != nil {
		t.Fatal("missing base_config accepted")
	}
}
