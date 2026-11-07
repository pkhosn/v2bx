package cmd

import (
	"net"
	"strings"
	"testing"
)

func TestHopRangesAndRules(t *testing.T) {
	for _, s := range []string{"40000-40009", "1024-1024", "64536-65535"} {
		a, b, e := hopRange(s)
		if e != nil {
			t.Fatal(e)
		}
		r, e := hopNft(a, b, 443, "ipv4")
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(r, "flush") || !strings.Contains(r, "fib daddr type local ct direction original") || !strings.Contains(r, "meta nfproto ipv4") {
			t.Fatal("unsafe rule", r)
		}
	}
	for _, s := range []string{"1-100", "40000", "40000-41000", "65535-65536", "5000-4000", "40000-40001; flush ruleset"} {
		if _, _, e := hopRange(s); e == nil {
			t.Fatal("invalid range accepted", s)
		}
	}
	if _, e := hopNft(40000, 40009, 40005, "ipv4"); e == nil {
		t.Fatal("overlap accepted")
	}
	if _, e := hopNft(40000, 40009, 443, "both"); e == nil {
		t.Fatal("invalid family accepted")
	}
}
func TestHopPortConflict(t *testing.T) {
	l, e := net.ListenPacket("udp4", "0.0.0.0:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.LocalAddr().(*net.UDPAddr).Port
	if e = checkHopPorts(p, p); e == nil {
		t.Fatal("occupied port accepted")
	}
	l.Close()
	if e = checkHopPorts(p, p); e != nil {
		t.Fatal(e)
	}
}
func TestHopPersistentUnit(t *testing.T) {
	s := hopUnitText("/usr/sbin/nft")
	for _, want := range []string{"Before=V2bX.service", "After=network-pre.target nftables.service", "RemainAfterExit=yes", "delete table inet v2bx_hy_hop", "WantedBy=multi-user.target"} {
		if !strings.Contains(s, want) {
			t.Fatal("missing", want)
		}
	}
	if strings.Contains(s, "flush ruleset") {
		t.Fatal("destructive rule")
	}
}
