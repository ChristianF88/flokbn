package ingestor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
)

// The hardcoded live parser that TCPIngestor used before it switched to the
// logparser format compiler. It is kept, verbatim apart from the "legacy"
// prefix on its names and the removed Request.IP assignment, as the reference
// the differential test (live_parser_diff_test.go) compares the compiled
// default live format with.
// It is not part of the build.

// legacyParseLine parses one access-log line (the "message" field of a lumberjack
// event) into out. malformed counts non-fatal field corruption (status/bytes
// kept as zero), mirroring the log-parser's malformed-field accounting.
func legacyParseLine(msg string, out *accesslog.Request) (malformed int, err error) {
	// 1. Extract IP
	spaceIdx := strings.IndexByte(msg, ' ')
	if spaceIdx == -1 {
		return 0, errors.New("invalid log format: no IP")
	}
	ipTok := msg[:spaceIdx]
	// IPv4-only: reject IPv6 at the boundary. IPv4 literals never contain a
	// colon; every IPv6 literal does, INCLUDING the IPv4-mapped "::ffff:a.b.c.d"
	// form whose net.ParseIP(...).To4() is non-nil and would otherwise flow
	// through as a usable IPv4. A To4()==nil guard alone misses that mapped form,
	// so gate on the colon first. IPv6 previously flowed through as IP=<v6> with
	// IPUint32=0 and was counted as a successful request; now the event is
	// rejected, never stored or appended, and counted via parseErrors
	// (ParseErrorsTotal), the operator-visible reject counter.
	if strings.IndexByte(ipTok, ':') != -1 {
		return 0, fmt.Errorf("IPv6 not supported (IPv4-only tool): %q", ipTok)
	}
	ip := net.ParseIP(ipTok)
	if ip == nil {
		return 0, errors.New("invalid IP")
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("IPv6 not supported (IPv4-only tool): %q", ipTok)
	}
	// (The original also stored ip in Request.IP here; that field is gone.)
	out.IPUint32 = binary.BigEndian.Uint32(ip4)

	// 2. Extract timestamp
	t, end, err := legacyLocateTimestamp(msg, spaceIdx)
	if err != nil {
		return 0, err
	}
	out.Timestamp = t

	// 3. Request line (after first quote). The closing quote must be escape-aware
	// so an Apache-escaped `\"` inside the URI does not terminate the field early.
	// This matches the static parser (parser.go scanQuotedClose) so live and
	// static align on the same byte offsets - and therefore extract the same
	// Method/URI/status/bytes/UserAgent - for adversary-controlled escaped quotes.
	start := strings.IndexByte(msg[end:], '"')
	if start == -1 {
		return 0, errors.New("missing request start quote")
	}
	start += end + 1
	end = legacyCloseQuote(msg, start)
	if end == -1 {
		return 0, errors.New("missing request end quote")
	}
	requestLine := msg[start:end]
	parts := strings.Fields(requestLine)
	if len(parts) >= 2 {
		out.Method = accesslog.ParseMethod(parts[0])
		out.URI = parts[1]
	}

	// 4. Status and bytes (keep-and-zero on corruption, but count it)
	// Bounds-check: when the closing request-line quote is the final byte of
	// the message, end == len(msg)-1 so end+2 == len(msg)+1, which would panic
	// on slice. Treat a truncated line as having no status/bytes tail (status
	// and bytes stay zero, not counted malformed) - same as any short line.
	var fields []string
	if end+2 <= len(msg) {
		fields = strings.Fields(msg[end+2:])
	}
	if len(fields) >= 2 {
		// "-" = absent (Apache convention): silent zero, NOT malformed - parity
		// with the static log parser (parser.go status/bytes handling). Anything
		// else non-numeric stays counted as malformed.
		if fields[0] == "-" {
			// absent status: leave out.Status == 0, not counted
		} else if status, err := strconv.Atoi(fields[0]); err == nil {
			out.Status = uint16(status)
		} else {
			malformed++
		}
		if fields[1] == "-" {
			// absent bytes: leave out.Bytes == 0, not counted
		} else if bytesSent, err := strconv.Atoi(fields[1]); err == nil {
			out.Bytes = uint32(bytesSent)
		} else {
			malformed++
		}
	}

	// 5. User-Agent: the second quoted field after the request line (request line
	// is quotes 1-2, referer is 3-4, UA is 5-6). Walk the quoted fields forward
	// from the request-line close quote (at `end`) using the SAME escape-aware
	// close-quote scan as the request line and as the static parser, so an
	// escaped `\"` inside the URI or the referer cannot shift the quote count and
	// capture the wrong substring as UserAgent. A missing 5th/6th quote leaves
	// UserAgent empty, preserving the prior missing-field behavior.
	//
	// pos starts just past the request-line closing quote.
	pos := end + 1
	// Referer field (quotes 3-4): skip its content escape-aware so an escaped
	// quote in the referer does not become the UA's opening quote.
	refOpen := strings.IndexByte(msg[pos:], '"')
	if refOpen != -1 {
		refStart := pos + refOpen + 1
		refClose := legacyCloseQuote(msg, refStart)
		if refClose != -1 {
			pos = refClose + 1
			// User-Agent field (quotes 5-6).
			uaOpen := strings.IndexByte(msg[pos:], '"')
			if uaOpen != -1 {
				uaStart := pos + uaOpen + 1
				uaClose := legacyCloseQuote(msg, uaStart)
				if uaClose != -1 {
					out.UserAgent = msg[uaStart:uaClose]
				}
			}
		}
	}

	return malformed, nil
}

// legacyLocateTimestamp finds and parses the bracketed timestamp of a log line.
// ipEnd is the index of the space that ends the client-IP token. It returns
// the time and the index of the closing ']'.
//
// The timestamp is located by POSITION, not by content: in the layout live
// mode reads (`%h ident user [time] "request" ...`) it is the fourth
// space-separated field. Searching for the first '[' anywhere instead let a
// bracket in the ident or user field (client-controlled via HTTP basic auth)
// be taken for the timestamp, which dropped the event. Lines that do not have
// the timestamp in fourth position (e.g. no ident/user fields) fall back to
// the first bracketed field after the IP, as before.
func legacyLocateTimestamp(msg string, ipEnd int) (time.Time, int, error) {
	pos := ipEnd + 1
	for i := 0; i < 2 && pos >= 0; i++ {
		if sp := strings.IndexByte(msg[pos:], ' '); sp >= 0 {
			pos += sp + 1
		} else {
			pos = -1
		}
	}
	if pos >= 0 && pos < len(msg) && msg[pos] == '[' {
		if t, end, err := legacyParseBracketTime(msg, pos); err == nil {
			return t, end, nil
		}
	}
	first := strings.IndexByte(msg[ipEnd:], '[')
	if first < 0 {
		return time.Time{}, 0, errors.New("invalid timestamp format")
	}
	return legacyParseBracketTime(msg, ipEnd+first)
}

// legacyParseBracketTime parses the timestamp whose opening '[' is at msg[open] and
// returns it with the index of the closing ']'.
func legacyParseBracketTime(msg string, open int) (time.Time, int, error) {
	n := strings.IndexByte(msg[open:], ']')
	if n < 0 {
		return time.Time{}, 0, errors.New("invalid timestamp format")
	}
	end := open + n
	field := msg[open+1 : end]
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", field)
	if err != nil {
		// Offset-less Common/Apache-Log field (e.g. "06/Jul/2025:19:57:26",
		// 20 bytes): treat the wall-clock as UTC, mirroring the static parser's
		// >=26-byte gate (parser.go parseTimestamp). A zone-less layout returns a
		// time located in time.UTC, byte-identical to static's time.Date(...,
		// time.UTC) for the same wall-clock - restoring live<->static parity
		// (AUDIT-07). The offset path is tried first, so well-formed +HHMM lines
		// do no extra work and incur no extra allocations; the fallback runs only
		// on the error path. Genuinely malformed brackets (e.g. "badtime") fail
		// both layouts and are still rejected.
		t, err = time.Parse("02/Jan/2006:15:04:05", field)
		if err != nil {
			return time.Time{}, 0, err
		}
	}
	return t, end, nil
}

// legacyCloseQuote returns the index of the closing quote of a quoted field whose
// content begins at contentStart, or -1 if there is no (unescaped) closing
// quote at/after contentStart. The fast path uses strings.IndexByte (SIMD on
// amd64); the escape-aware slow path runs only when a candidate closing quote
// is immediately preceded by a backslash, so clean lines never pay for it.
// Field content keeps its raw escape bytes - this fixes field ALIGNMENT, not
// unescaping - matching the static parser exactly.
func legacyCloseQuote(s string, contentStart int) int {
	idx := strings.IndexByte(s[contentStart:], '"')
	if idx < 0 {
		return -1
	}
	q := contentStart + idx
	if idx > 0 && s[q-1] == '\\' {
		// rare slow path: the candidate quote may be escaped.
		c := legacyScanQuotedCloseStr(s, contentStart, q)
		if c >= len(s) {
			return -1 // no unescaped closing quote before end of message
		}
		return c
	}
	return q
}

// legacyScanQuotedCloseStr is a string-typed, byte-identical port of the static
// parser's scanQuotedClose (logparser/parser.go). ingestor is a leaf package
// and logparser imports it, so ingestor cannot import logparser (import cycle);
// the logic is duplicated here and proven identical to scanQuotedClose by the
// cross-package parity test in logparser. A quote is escaped iff preceded by an
// ODD number of consecutive backslashes back to contentStart. Returns the index
// of the first unescaped quote at/after firstQuote, or len(s).
func legacyScanQuotedCloseStr(s string, contentStart, firstQuote int) int {
	i := firstQuote
	for {
		bs := 0
		for j := i - 1; j >= contentStart && s[j] == '\\'; j-- {
			bs++
		}
		if bs%2 == 0 {
			return i
		}
		next := strings.IndexByte(s[i+1:], '"')
		if next < 0 {
			return len(s)
		}
		i += 1 + next
	}
}
