package cidr

import (
	"net"
	"testing"
)

func FuzzNumericCIDR_String(f *testing.F) {
	seeds := []struct {
		ip        uint32
		prefixLen uint8
	}{
		{0xC0A80100, 24}, // 192.168.1.0/24
		{0x0A000000, 8},  // 10.0.0.0/8
		{0, 0},           // 0.0.0.0/0
		{0xFFFFFFFF, 32}, // 255.255.255.255/32
		{0x01010101, 16}, // 1.1.1.1/16
	}
	for _, s := range seeds {
		f.Add(s.ip, s.prefixLen)
	}

	f.Fuzz(func(t *testing.T, ip uint32, prefixLen uint8) {
		nc := NumericCIDR{IP: ip, PrefixLen: prefixLen}
		// Should not panic
		result := nc.String()
		if prefixLen <= 32 && result == "" {
			t.Error("String() returned empty for valid prefix length")
		}
	})
}

func FuzzMergeCIDRs(f *testing.F) {
	seeds := []string{
		"10.0.0.0/8",
		"10.0.0.0/16",
		"192.168.1.0/24",
		"192.168.1.0/25",
		"172.16.0.0/12",
		"invalid",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, cidr string) {
		// Skip unparseable inputs; single CIDR merge should not panic
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Skip()
		}
		MergeIPNets([]*net.IPNet{ipNet})
	})
}
