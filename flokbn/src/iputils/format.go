package iputils

// MaxIPv4Len is the length of the longest dotted-quad IPv4 string,
// "255.255.255.255".
const MaxIPv4Len = 15

// PutUint8 writes the decimal form of v (no padding, 1 to 3 bytes) into buf
// starting at pos and returns the position after the last byte written. It is
// the one octet formatter behind the IPv4 strings flokbn builds itself
// (accesslog.Uint32ToIPString, cidr.NumericCIDR.String).
//
// Index-based instead of append-style on purpose: writing into a fixed stack
// buffer this way measured faster than appending to it.
func PutUint8(buf []byte, pos int, v uint8) int {
	if v >= 100 {
		buf[pos] = '0' + v/100
		buf[pos+1] = '0' + (v%100)/10
		buf[pos+2] = '0' + v%10
		return pos + 3
	}
	if v >= 10 {
		buf[pos] = '0' + v/10
		buf[pos+1] = '0' + v%10
		return pos + 2
	}
	buf[pos] = '0' + v
	return pos + 1
}

// PutIPv4 writes ip in dotted-quad notation at the start of buf and returns
// the number of bytes written (at most MaxIPv4Len; buf must have room for
// them). ip is in network byte order: the first octet is the most significant
// byte.
func PutIPv4(buf []byte, ip uint32) int {
	pos := PutUint8(buf, 0, byte(ip>>24))
	buf[pos] = '.'
	pos = PutUint8(buf, pos+1, byte(ip>>16))
	buf[pos] = '.'
	pos = PutUint8(buf, pos+1, byte(ip>>8))
	buf[pos] = '.'
	return PutUint8(buf, pos+1, byte(ip))
}
