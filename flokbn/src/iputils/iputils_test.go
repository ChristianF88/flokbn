package iputils

import (
	"net"
	"testing"
)

func TestIPToUint32(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected uint32
	}{
		{
			name:     "127.0.0.1",
			ip:       "127.0.0.1",
			expected: 2130706433, // 0x7F000001
		},
		{
			name:     "192.168.1.1",
			ip:       "192.168.1.1",
			expected: 3232235777, // 0xC0A80101
		},
		{
			name:     "0.0.0.0",
			ip:       "0.0.0.0",
			expected: 0,
		},
		{
			name:     "255.255.255.255",
			ip:       "255.255.255.255",
			expected: 4294967295, // 0xFFFFFFFF
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := IPToUint32(ip)
			if result != tt.expected {
				t.Errorf("IPToUint32(%s) = %d, expected %d", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected string
	}{
		{
			name:     "127.0.0.1",
			input:    2130706433,
			expected: "127.0.0.1",
		},
		{
			name:     "192.168.1.1",
			input:    3232235777,
			expected: "192.168.1.1",
		},
		{
			name:     "0.0.0.0",
			input:    0,
			expected: "0.0.0.0",
		},
		{
			name:     "255.255.255.255",
			input:    4294967295,
			expected: "255.255.255.255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Uint32ToIP(tt.input)
			if result.String() != tt.expected {
				t.Errorf("Uint32ToIP(%d) = %s, expected %s", tt.input, result.String(), tt.expected)
			}
		})
	}
}

func TestIsValidCidrOrIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Valid IPv4",
			input:    "192.168.1.1",
			expected: true,
		},
		{
			name:     "Valid CIDR",
			input:    "192.168.1.0/24",
			expected: true,
		},
		{
			name:     "Invalid IP",
			input:    "999.999.999.999",
			expected: false,
		},
		{
			name:     "Invalid CIDR",
			input:    "192.168.1.0/33",
			expected: false,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidCidrOrIP(tt.input)
			if result != tt.expected {
				t.Errorf("IsValidCidrOrIP(%s) = %t, expected %t", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRoundTripConversion(t *testing.T) {
	testIPs := []string{
		"127.0.0.1",
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"255.255.255.255",
		"0.0.0.0",
	}

	for _, ipStr := range testIPs {
		t.Run(ipStr, func(t *testing.T) {
			originalIP := net.ParseIP(ipStr)
			uint32Val := IPToUint32(originalIP)
			convertedIP := Uint32ToIP(uint32Val)

			if !originalIP.Equal(convertedIP) {
				t.Errorf("Round-trip conversion failed for %s: got %s", ipStr, convertedIP.String())
			}
		})
	}
}
