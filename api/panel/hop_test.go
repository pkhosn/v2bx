package panel

import (
	"fmt"
	"net/http"
	"testing"
)

func TestHY2OptionalSubscriptionPorts(t *testing.T) {
	for _, ports := range []string{"", `,"port":40000,"mport":"40000-40009"`} {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"server_port":36005,"server_name":"node.example.com","base_config":{"push_interval":60,"pull_interval":60}%s}`, ports)
		})
		c.NodeType = "hysteria2"
		n, err := c.GetNodeInfo()
		if err != nil {
			t.Fatal(err)
		}
		if n.Hysteria2.ServerPort != 36005 {
			t.Fatal("listener port replaced by connection range")
		}
		if (len(n.Hysteria2.MPort) > 0) != (ports != "") {
			t.Fatal("optional hop range lost")
		}
	}
}
