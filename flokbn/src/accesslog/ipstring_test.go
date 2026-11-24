package accesslog

import (
	"math/rand"
	"testing"

	"github.com/ChristianF88/flokbn/iputils"
)

func TestUint32ToIPString(t *testing.T) {
	for ip, want := range map[uint32]string{
		0:          "0.0.0.0",
		0x01020304: "1.2.3.4",
		0x0A000001: "10.0.0.1",
		0x63646465: "99.100.100.101",
		0xC0A80001: "192.168.0.1",
		0xFFFFFFFF: "255.255.255.255",
	} {
		if got := Uint32ToIPString(ip); got != want {
			t.Errorf("Uint32ToIPString(%#x) = %q, want %q", ip, got, want)
		}
	}

	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 20000; i++ {
		ip := rng.Uint32()
		if got, want := Uint32ToIPString(ip), iputils.Uint32ToIP(ip).String(); got != want {
			t.Fatalf("Uint32ToIPString(%#x) = %q, want %q", ip, got, want)
		}
	}

	if allocs := testing.AllocsPerRun(100, func() { _ = Uint32ToIPString(0xFFFFFFFF) }); allocs > 1 {
		t.Errorf("Uint32ToIPString allocates %v times, want at most 1 (the string)", allocs)
	}
}

// ipStringSink keeps the result alive so the string allocation is measured.
var ipStringSink string

func BenchmarkUint32ToIPString(b *testing.B) {
	ips := []uint32{0x0A000000, 0xC0A80100, 0xFFFFFFFF, 0x01020304}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ipStringSink = Uint32ToIPString(ips[i&3])
	}
}
