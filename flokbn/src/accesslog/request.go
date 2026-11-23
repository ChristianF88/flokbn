// Package accesslog holds the record one access-log line is parsed into. It
// is a leaf package: the log parser fills a Request, the live ingestor and
// the static pipeline pass it on, and none of them has to import another to
// name the type.
package accesslog

import (
	"net"
	"time"
)

type HTTPMethod uint8

const (
	GET HTTPMethod = iota
	POST
	PUT
	DELETE
	HEAD
	OPTIONS
	PATCH
	UNKNOWN
)

func ParseMethod(m string) HTTPMethod {
	switch m {
	case "GET":
		return GET
	case "POST":
		return POST
	case "PUT":
		return PUT
	case "DELETE":
		return DELETE
	case "HEAD":
		return HEAD
	case "OPTIONS":
		return OPTIONS
	case "PATCH":
		return PATCH
	default:
		return UNKNOWN
	}
}

type Request struct {
	// Hot fields - first cache line (accessed by trie insertion, filtering, clustering)
	IPUint32  uint32     // Primary IP storage - eliminates net.IP allocation in parser
	Status    uint16     // Smaller type for status code
	Method    HTTPMethod // 1 byte
	_         byte       // explicit padding for alignment
	Bytes     uint32
	Timestamp time.Time // 24 bytes - needed for time-range filtering

	// Cold fields - second cache line (only accessed during output or string filtering)
	URI       string
	UserAgent string
	IP        net.IP // Legacy (TCP ingestor path only, nil from log parser)
}

// GetIPNet returns the IP as net.IP, deriving from IPUint32 if IP is nil.
// Use this for non-hot-path code that needs net.IP.
func (r *Request) GetIPNet() net.IP {
	if r.IP != nil {
		return r.IP
	}
	if r.IPUint32 == 0 {
		return nil
	}
	return net.IPv4(byte(r.IPUint32>>24), byte(r.IPUint32>>16), byte(r.IPUint32>>8), byte(r.IPUint32))
}
