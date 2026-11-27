package testutil

import (
	"crypto/rand"
	"fmt"
	"net"

	"github.com/ChristianF88/flokbn/iputils"
)

// RandomIPsFromRange returns count random IPv4 addresses inside cidr. For a
// /30 or wider range it leaves out the network and broadcast address; a /31
// yields both addresses, a /32 its one address count times.
func RandomIPsFromRange(cidr string, count int) ([]net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if _, bits := ipnet.Mask.Size(); bits != 32 {
		return nil, fmt.Errorf("only IPv4 is supported")
	}

	baseIP := iputils.IPToUint32(ipnet.IP)
	span := ^iputils.IPToUint32(net.IP(ipnet.Mask)) // last address - base address

	ipList := make([]net.IP, 0, count)
	for len(ipList) < count {
		offset := uint32(0)
		switch {
		case span == 1:
			if offset, err = randUint32Range(0, 2); err != nil {
				return nil, err
			}
		case span > 1:
			if offset, err = randUint32Range(1, span); err != nil {
				return nil, err
			}
		}
		ipList = append(ipList, iputils.Uint32ToIP(baseIP+offset))
	}
	return ipList, nil
}

// randUint32Range returns a random uint32 in [min, max).
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
