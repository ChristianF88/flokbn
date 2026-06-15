package iputils

import (
	"crypto/rand"
	"fmt"
	"net"
)

// IPToUint32 converts a net.IP to uint32 representation
// Uses BigEndian encoding for consistent network byte order
func IPToUint32(ip net.IP) uint32 {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0
	}
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
}

// Uint32ToIP converts a uint32 back to net.IP
func Uint32ToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

// IsValidCidrOrIP checks if string is a valid CIDR or IP address
func IsValidCidrOrIP(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	return false
}

// RandomIPsFromRange generates random IP addresses within a CIDR range.
// It is a test-data generator with no production callers; it is kept because
// tests and benchmarks in four packages use it to synthesize IP corpora.
func RandomIPsFromRange(cidr string, count int) ([]net.IP, error) {
	ipList := make([]net.IP, 0, count)

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// The number of leading 1s in the mask
	_, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only IPv4 is supported")
	}

	// Convert the base IP to an integer
	baseIP := IPToUint32(ipnet.IP)
	lastIP := IPToUint32(lastIPInRange(ipnet))

	for len(ipList) < count {
		randomOffset, err := randUint32Range(1, lastIP-baseIP) // Avoid network (0) and broadcast (lastIP-baseIP+1)
		if err != nil {
			return nil, err
		}

		randomIP := Uint32ToIP(baseIP + randomOffset)
		ipList = append(ipList, randomIP)
	}

	return ipList, nil
}

// randUint32Range generates a random uint32 in the range [min, max)
func randUint32Range(min, max uint32) (uint32, error) {
	if min >= max {
		return 0, fmt.Errorf("invalid range")
	}
	r := make([]byte, 4)
	if _, err := rand.Read(r); err != nil {
		return 0, err
	}
	randomValue := uint32(r[0])<<24 | uint32(r[1])<<16 | uint32(r[2])<<8 | uint32(r[3])
	return min + randomValue%(max-min), nil
}

// lastIPInRange returns the last IP in a CIDR range
func lastIPInRange(ipnet *net.IPNet) net.IP {
	ip := make(net.IP, len(ipnet.IP))
	copy(ip, ipnet.IP)
	for i := range ip {
		ip[i] |= ^ipnet.Mask[i]
	}
	return ip
}
