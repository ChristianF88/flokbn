package iputils

import (
	"net"
	"testing"
)

func TestNormalizeIPv4CIDR(t *testing.T) {
	tests := []struct {
		input  string
		want   string
		wantOK bool
	}{
		{"192.168.1.0/24", "192.168.1.0/24", true},
		{"0.0.0.0/0", "0.0.0.0/0", true},
		{"10.0.0.77/24", "10.0.0.77/24", true}, // host bits are left for the consumer
		{"1.2.3.4", "1.2.3.4/32", true},        // bare IPv4 -> single host
		{"255.255.255.255", "255.255.255.255/32", true},
		{"1.2.3.4/32", "1.2.3.4/32", true},

		{"", "", false},
		{"not-an-ip", "", false},
		{"1.2.3", "", false},
		{"1.2.3.4/33", "", false},
		{"1.2.3.4/", "", false},
		{"999.1.1.1", "", false},
		{" 1.2.3.4", "", false},
		{"::1", "", false},
		{"2001:db8::/32", "", false},
		{"2001:db8::1", "", false},
		{"::ffff:192.168.1.1", "", false},
		{"::ffff:192.168.1.0/120", "", false},
	}
	for _, tt := range tests {
		got, ok := NormalizeIPv4CIDR(tt.input)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("NormalizeIPv4CIDR(%q) = (%q, %v), want (%q, %v)", tt.input, got, ok, tt.want, tt.wantOK)
		}
	}
}

// Whatever IsValidCidrOrIP accepts, NormalizeIPv4CIDR must turn into something
// net.ParseCIDR parses as an IPv4 network: the gap between the two was the bug
// (a bare IP passed validation and then failed in trie.CountInRange).
func FuzzNormalizeIPv4CIDR(f *testing.F) {
	for _, s := range []string{"192.168.1.0/24", "10.0.0.1", "0.0.0.0/0", "::1/128", "::ffff:1.2.3.4", "1.2.3.4/33", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, ok := NormalizeIPv4CIDR(s)
		if ok != IsValidCidrOrIP(s) {
			t.Fatalf("NormalizeIPv4CIDR(%q) ok=%v disagrees with IsValidCidrOrIP=%v", s, ok, IsValidCidrOrIP(s))
		}
		if !ok {
			if got != "" {
				t.Fatalf("NormalizeIPv4CIDR(%q) returned %q with ok=false", s, got)
			}
			return
		}
		_, ipNet, err := net.ParseCIDR(got)
		if err != nil {
			t.Fatalf("NormalizeIPv4CIDR(%q) = %q, which net.ParseCIDR rejects: %v", s, got, err)
		}
		if len(ipNet.Mask) != 4 {
			t.Fatalf("NormalizeIPv4CIDR(%q) = %q is not an IPv4 network", s, got)
		}
	})
}
