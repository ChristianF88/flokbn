package testutil

import "github.com/ChristianF88/flokbn/accesslog"

// ParseMethod maps an HTTP method name to accesslog.HTTPMethod (UNKNOWN for
// anything else). The legacy parsers kept as test oracles use it; the
// production parsers decode the method in place (logparser.parseMethod).
func ParseMethod(m string) accesslog.HTTPMethod {
	switch m {
	case "GET":
		return accesslog.GET
	case "POST":
		return accesslog.POST
	case "PUT":
		return accesslog.PUT
	case "DELETE":
		return accesslog.DELETE
	case "HEAD":
		return accesslog.HEAD
	case "OPTIONS":
		return accesslog.OPTIONS
	case "PATCH":
		return accesslog.PATCH
	default:
		return accesslog.UNKNOWN
	}
}
