package iputils

import (
	"math"
	"net"
	"testing"
)

func FuzzIPToUint32(f *testing.F) {
	seeds := []string{
		"192.168.1.1",
		"0.0.0.0",
		"255.255.255.255",
		"10.0.0.1",
		"::1",
		"",
		"not-an-ip",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		ip := net.ParseIP(s)
		if ip == nil {
			return
		}
		// Should not panic
		_ = IPToUint32(ip)
	})
}

func FuzzUint32ToIP(f *testing.F) {
	seeds := []uint32{0, 1, math.MaxUint32, 0xC0A80101, 0x0A000001}
	for _, v := range seeds {
		f.Add(v)
	}

	f.Fuzz(func(t *testing.T, v uint32) {
		// Should not panic
		ip := Uint32ToIP(v)
		if ip == nil {
			t.Error("Uint32ToIP returned nil")
		}
	})
}

func FuzzIsValidCidrOrIP(f *testing.F) {
	seeds := []string{
		"192.168.1.0/24",
		"10.0.0.1",
		"0.0.0.0/0",
		"255.255.255.255/32",
		"invalid",
		"",
		"192.168.1.0/33",
		"::1/128",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		// Should not panic, just return a bool
		_ = IsValidCidrOrIP(s)
	})
}
