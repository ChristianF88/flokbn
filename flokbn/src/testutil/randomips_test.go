package testutil

import (
	"net"
	"testing"

	"github.com/ChristianF88/flokbn/iputils"
)

func TestRandomIPsFromRange_SlashThirtyTwo(t *testing.T) {
	const n = 16
	ips, err := RandomIPsFromRange("192.168.1.5/32", n)
	if err != nil {
		t.Fatalf("RandomIPsFromRange(/32) unexpected error: %v", err)
	}
	if len(ips) != n {
		t.Fatalf("RandomIPsFromRange(/32) returned %d IPs, want %d", len(ips), n)
	}
	want := net.ParseIP("192.168.1.5")
	for i, ip := range ips {
		if !ip.Equal(want) {
			t.Errorf("RandomIPsFromRange(/32)[%d] = %s, want 192.168.1.5", i, ip.String())
		}
	}
}

func TestRandomIPsFromRange_SlashThirtyOne(t *testing.T) {
	const n = 64
	ips, err := RandomIPsFromRange("192.168.1.4/31", n)
	if err != nil {
		t.Fatalf("RandomIPsFromRange(/31) unexpected error: %v", err)
	}
	if len(ips) != n {
		t.Fatalf("RandomIPsFromRange(/31) returned %d IPs, want %d", len(ips), n)
	}
	a := net.ParseIP("192.168.1.4")
	b := net.ParseIP("192.168.1.5")
	for i, ip := range ips {
		if !ip.Equal(a) && !ip.Equal(b) {
			t.Errorf("RandomIPsFromRange(/31)[%d] = %s, want one of {192.168.1.4, 192.168.1.5}", i, ip.String())
		}
	}
}

func TestRandomIPsFromRange_SlashThirty(t *testing.T) {
	const n = 64
	ips, err := RandomIPsFromRange("192.168.1.0/30", n)
	if err != nil {
		t.Fatalf("RandomIPsFromRange(/30) unexpected error: %v", err)
	}
	if len(ips) != n {
		t.Fatalf("RandomIPsFromRange(/30) returned %d IPs, want %d", len(ips), n)
	}
	// /30 host range avoids network (.0) and broadcast (.3); usable .1 and .2.
	lo := iputils.IPToUint32(net.ParseIP("192.168.1.0"))
	hi := iputils.IPToUint32(net.ParseIP("192.168.1.3"))
	for i, ip := range ips {
		v := iputils.IPToUint32(ip)
		if v <= lo || v >= hi {
			t.Errorf("RandomIPsFromRange(/30)[%d] = %s, out of usable host range (.1-.2)", i, ip.String())
		}
	}
}
