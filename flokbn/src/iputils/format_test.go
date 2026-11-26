package iputils

import (
	"math/rand"
	"strconv"
	"testing"
)

func TestPutUint8(t *testing.T) {
	for v := 0; v <= 255; v++ {
		var buf [3]byte
		n := PutUint8(buf[:], 0, uint8(v))
		if got, want := string(buf[:n]), strconv.Itoa(v); got != want {
			t.Errorf("PutUint8(%d) = %q, want %q", v, got, want)
		}
	}

	// At an offset, leaving what is before it alone.
	buf := []byte("x/___")
	if n := PutUint8(buf, 2, 24); n != 4 || string(buf[:n]) != "x/24" {
		t.Errorf("PutUint8 at offset 2 = %q (end %d), want %q (end 4)", buf[:n], n, "x/24")
	}
}

// TestPutIPv4 compares with net.IP.String for the octet-width edges and a
// random sample.
func TestPutIPv4(t *testing.T) {
	ips := []uint32{
		0, 1, 9, 10, 99, 100, 255,
		0x01020304, 0x0A000000, 0x0A0A0A0A, 0x63636363, 0x64646464,
		0x7F000001, 0xC0A80001, 0xC0A801FF, 0xFFFFFFFE, 0xFFFFFFFF,
	}
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 20000; i++ {
		ips = append(ips, rng.Uint32())
	}
	for _, ip := range ips {
		var buf [MaxIPv4Len]byte
		n := PutIPv4(buf[:], ip)
		if got, want := string(buf[:n]), Uint32ToIP(ip).String(); got != want {
			t.Fatalf("PutIPv4(%#x) = %q, want %q", ip, got, want)
		}
	}
}
