package accesslog

import "github.com/ChristianF88/flokbn/iputils"

// Uint32ToIPString converts uint32 back to IP string for output
func Uint32ToIPString(ip uint32) string {
	// Formatted into a stack buffer: the string is the only allocation.
	var buf [iputils.MaxIPv4Len]byte
	n := iputils.PutIPv4(buf[:], ip)
	return string(buf[:n])
}
