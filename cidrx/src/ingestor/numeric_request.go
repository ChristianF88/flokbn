package ingestor

import (
	"time"
)

// NumericRequest uses uint32 for IP addresses to eliminate conversions
// This version keeps everything in numeric format until final output
type NumericRequest struct {
	Timestamp time.Time // Use native time
	IP        uint32    // Store IP as uint32 - NO MORE net.IP conversions!
	URI       string
	UserAgent string
	Method    HTTPMethod
	Status    uint16 // Smaller type for status code
	Bytes     uint32
}

// Uint32ToIPString converts uint32 back to IP string for output
func Uint32ToIPString(ip uint32) string {
	// Use a pre-allocated byte buffer to avoid allocations
	var buf [15]byte // Max IPv4 length: "255.255.255.255"

	b1 := byte(ip >> 24)
	b2 := byte(ip >> 16)
	b3 := byte(ip >> 8)
	b4 := byte(ip)

	pos := 0

	// Convert first octet
	if b1 >= 100 {
		buf[pos] = '0' + b1/100
		pos++
		buf[pos] = '0' + (b1%100)/10
		pos++
		buf[pos] = '0' + b1%10
		pos++
	} else if b1 >= 10 {
		buf[pos] = '0' + b1/10
		pos++
		buf[pos] = '0' + b1%10
		pos++
	} else {
		buf[pos] = '0' + b1
		pos++
	}
	buf[pos] = '.'
	pos++

	// Convert second octet
	if b2 >= 100 {
		buf[pos] = '0' + b2/100
		pos++
		buf[pos] = '0' + (b2%100)/10
		pos++
		buf[pos] = '0' + b2%10
		pos++
	} else if b2 >= 10 {
		buf[pos] = '0' + b2/10
		pos++
		buf[pos] = '0' + b2%10
		pos++
	} else {
		buf[pos] = '0' + b2
		pos++
	}
	buf[pos] = '.'
	pos++

	// Convert third octet
	if b3 >= 100 {
		buf[pos] = '0' + b3/100
		pos++
		buf[pos] = '0' + (b3%100)/10
		pos++
		buf[pos] = '0' + b3%10
		pos++
	} else if b3 >= 10 {
		buf[pos] = '0' + b3/10
		pos++
		buf[pos] = '0' + b3%10
		pos++
	} else {
		buf[pos] = '0' + b3
		pos++
	}
	buf[pos] = '.'
	pos++

	// Convert fourth octet
	if b4 >= 100 {
		buf[pos] = '0' + b4/100
		pos++
		buf[pos] = '0' + (b4%100)/10
		pos++
		buf[pos] = '0' + b4%10
		pos++
	} else if b4 >= 10 {
		buf[pos] = '0' + b4/10
		pos++
		buf[pos] = '0' + b4%10
		pos++
	} else {
		buf[pos] = '0' + b4
		pos++
	}

	return string(buf[:pos])
}
