package ingestor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lj "github.com/elastic/go-lumber/lj"
	srv2 "github.com/elastic/go-lumber/server/v2"
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
	// Hot fields — first cache line (accessed by trie insertion, filtering, clustering)
	IPUint32  uint32     // Primary IP storage - eliminates net.IP allocation in parser
	Status    uint16     // Smaller type for status code
	Method    HTTPMethod // 1 byte
	_         byte       // explicit padding for alignment
	Bytes     uint32
	Timestamp time.Time // 24 bytes — needed for time-range filtering

	// Cold fields — second cache line (only accessed during output or string filtering)
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

// --- TCP Ingestor using go-lumber v2 ---

// Ingestor is the contract the live loop consumes. TCPIngestor is the
// lumberjack/TCP implementation; FLOKBN-037 will add a file-tailing one.
type Ingestor interface {
	Accept() error
	ReadBatch() ([]Request, error)
	IsClosed() bool
	Close() error
	Stats() IngestStats
}

// IngestStats is a point-in-time view of the ingestor's counters.
type IngestStats struct {
	QueueDepth           int
	BatchesTotal         uint64
	RequestsTotal        uint64
	ParseErrorsTotal     uint64
	MalformedFieldsTotal uint64
	LastBatchAt          time.Time // zero until the first batch is read
}

var _ Ingestor = (*TCPIngestor)(nil)

type TCPIngestor struct {
	listener    net.Listener
	readTimeout time.Duration // for server
	events      chan *lj.Batch
	server      *srv2.Server
	closed      atomic.Bool
	closeOnce   sync.Once
	closeErr    error

	batchesTotal    atomic.Uint64
	requestsTotal   atomic.Uint64
	parseErrors     atomic.Uint64
	malformedFields atomic.Uint64
	lastBatchUnixNs atomic.Int64
}

func NewTCPIngestor(addr string, readTimeout time.Duration) (*TCPIngestor, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	return &TCPIngestor{
		listener:    ln,
		readTimeout: readTimeout,
		events:      make(chan *lj.Batch, 1000),
	}, nil
}

// Addr returns the listener address. Useful when listening on an ephemeral
// port (e.g. "127.0.0.1:0" in tests).
func (ing *TCPIngestor) Addr() net.Addr {
	return ing.listener.Addr()
}

// Accept starts the lumberjack v2 Server.
func (ing *TCPIngestor) Accept() error {
	srv, err := srv2.NewWithListener(
		ing.listener,
		srv2.Timeout(ing.readTimeout),
	)
	if err != nil {
		return fmt.Errorf("failed to create lumberjack server: %w", err)
	}
	ing.server = srv

	// Pull batches off ReceiveChan and ack them.
	go func() {
		for batch := range ing.server.ReceiveChan() {
			ing.events <- batch
			batch.ACK()
		}
		ing.closed.Store(true)
		close(ing.events)
	}()

	return nil
}

// parseEvent parses one lumberjack event into out. malformed counts
// non-fatal field corruption (status/bytes kept as zero), mirroring the
// log-parser's malformed-field accounting.
func parseEvent(evt map[string]interface{}, out *Request) (malformed int, err error) {
	msg, ok := evt["message"].(string)
	if !ok {
		return 0, errors.New("missing message field")
	}

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
	out.IP = ip
	out.IPUint32 = binary.BigEndian.Uint32(ip4)

	// 2. Extract timestamp
	start := strings.IndexByte(msg, '[')
	end := strings.IndexByte(msg, ']')
	if start < 0 || end <= start {
		return 0, errors.New("invalid timestamp format")
	}
	field := msg[start+1 : end]
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", field)
	if err != nil {
		// Offset-less Common/Apache-Log field (e.g. "06/Jul/2025:19:57:26",
		// 20 bytes): treat the wall-clock as UTC, mirroring the static parser's
		// >=26-byte gate (parser.go parseTimestamp). A zone-less layout returns a
		// time located in time.UTC, byte-identical to static's time.Date(...,
		// time.UTC) for the same wall-clock — restoring live<->static parity
		// (AUDIT-07). The offset path is tried first, so well-formed +HHMM lines
		// do no extra work and incur no extra allocations; the fallback runs only
		// on the error path. Genuinely malformed brackets (e.g. "badtime") fail
		// both layouts and are still rejected.
		t, err = time.Parse("02/Jan/2006:15:04:05", field)
		if err != nil {
			return 0, err
		}
	}
	out.Timestamp = t

	// 3. Request line (after first quote). The closing quote must be escape-aware
	// so an Apache-escaped `\"` inside the URI does not terminate the field early.
	// This matches the static parser (parser.go scanQuotedClose) so live and
	// static align on the same byte offsets — and therefore extract the same
	// Method/URI/status/bytes/UserAgent — for adversary-controlled escaped quotes.
	start = strings.IndexByte(msg[end:], '"')
	if start == -1 {
		return 0, errors.New("missing request start quote")
	}
	start += end + 1
	end = closeQuote(msg, start)
	if end == -1 {
		return 0, errors.New("missing request end quote")
	}
	requestLine := msg[start:end]
	parts := strings.Fields(requestLine)
	if len(parts) >= 2 {
		out.Method = ParseMethod(parts[0])
		out.URI = parts[1]
	}

	// 4. Status and bytes (keep-and-zero on corruption, but count it)
	// Bounds-check: when the closing request-line quote is the final byte of
	// the message, end == len(msg)-1 so end+2 == len(msg)+1, which would panic
	// on slice. Treat a truncated line as having no status/bytes tail (status
	// and bytes stay zero, not counted malformed) — same as any short line.
	var fields []string
	if end+2 <= len(msg) {
		fields = strings.Fields(msg[end+2:])
	}
	if len(fields) >= 2 {
		// "-" = absent (Apache convention): silent zero, NOT malformed — parity
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
		refClose := closeQuote(msg, refStart)
		if refClose != -1 {
			pos = refClose + 1
			// User-Agent field (quotes 5-6).
			uaOpen := strings.IndexByte(msg[pos:], '"')
			if uaOpen != -1 {
				uaStart := pos + uaOpen + 1
				uaClose := closeQuote(msg, uaStart)
				if uaClose != -1 {
					out.UserAgent = msg[uaStart:uaClose]
				}
			}
		}
	}

	return malformed, nil
}

// closeQuote returns the index of the closing quote of a quoted field whose
// content begins at contentStart, or -1 if there is no (unescaped) closing
// quote at/after contentStart. The fast path uses strings.IndexByte (SIMD on
// amd64); the escape-aware slow path runs only when a candidate closing quote
// is immediately preceded by a backslash, so clean lines never pay for it.
// Field content keeps its raw escape bytes — this fixes field ALIGNMENT, not
// unescaping — matching the static parser exactly.
func closeQuote(s string, contentStart int) int {
	idx := strings.IndexByte(s[contentStart:], '"')
	if idx < 0 {
		return -1
	}
	q := contentStart + idx
	if idx > 0 && s[q-1] == '\\' {
		// rare slow path: the candidate quote may be escaped.
		c := scanQuotedCloseStr(s, contentStart, q)
		if c >= len(s) {
			return -1 // no unescaped closing quote before end of message
		}
		return c
	}
	return q
}

// scanQuotedCloseStr is a string-typed, byte-identical port of the static
// parser's scanQuotedClose (logparser/parser.go). ingestor is a leaf package
// and logparser imports it, so ingestor cannot import logparser (import cycle);
// the logic is duplicated here and proven identical to scanQuotedClose by the
// cross-package parity test in logparser. A quote is escaped iff preceded by an
// ODD number of consecutive backslashes back to contentStart. Returns the index
// of the first unescaped quote at/after firstQuote, or len(s).
func scanQuotedCloseStr(s string, contentStart, firstQuote int) int {
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

// parseEventSafe parses a single event, recovering from any panic in
// parseEvent so one malformed (untrusted) event can never crash the live-loop
// goroutine. A recovered panic is surfaced as an error so the caller counts it
// as a parse error and skips the event (never appended, never zero-valued into
// output).
func parseEventSafe(m map[string]interface{}, out *Request) (malformed int, err error) {
	defer func() {
		if r := recover(); r != nil {
			malformed = 0
			err = fmt.Errorf("parseEvent panic: %v", r)
		}
	}()
	return parseEvent(m, out)
}

// ParseEventForTest parses a single raw log line through the live ingestor's
// parseEvent and returns the resulting Request. It exists solely so the
// live<->static UserAgent parity test (logparser/parser_live_ua_parity_test.go)
// can drive the live parser from a package that ALSO compiles the static format
// — ingestor is a leaf package that logparser imports, so the parity test cannot
// live in ingestor (it would have to import logparser, an import cycle). This is
// a thin wrapper over the unexported parseEvent and is not part of the live data
// path (ReadBatch uses parseEventSafe directly).
func ParseEventForTest(line string) (Request, error) {
	var req Request
	_, err := parseEvent(map[string]interface{}{"message": line}, &req)
	return req, err
}

func (ing *TCPIngestor) ReadBatch() ([]Request, error) {
	var out []Request

	for {
		select {
		case batch, ok := <-ing.events:
			if !ok {
				return out, nil
			}
			ing.batchesTotal.Add(1)
			ing.lastBatchUnixNs.Store(time.Now().UnixNano())
			for _, evt := range batch.Events {
				if m, ok := evt.(map[string]interface{}); ok {
					var entry Request
					if malformed, err := parseEventSafe(m, &entry); err == nil {
						if malformed > 0 {
							ing.malformedFields.Add(uint64(malformed))
						}
						ing.requestsTotal.Add(1)
						out = append(out, entry)
					} else {
						ing.parseErrors.Add(1)
					}
				}
			}
		default:
			// Channel is empty, return what we have
			return out, nil
		}
	}
}

// Stats returns a point-in-time view of the ingestor counters. Safe to call
// concurrently with ReadBatch.
func (ing *TCPIngestor) Stats() IngestStats {
	st := IngestStats{
		QueueDepth:           len(ing.events),
		BatchesTotal:         ing.batchesTotal.Load(),
		RequestsTotal:        ing.requestsTotal.Load(),
		ParseErrorsTotal:     ing.parseErrors.Load(),
		MalformedFieldsTotal: ing.malformedFields.Load(),
	}
	if ns := ing.lastBatchUnixNs.Load(); ns != 0 {
		st.LastBatchAt = time.Unix(0, ns)
	}
	return st
}

func (ing *TCPIngestor) IsClosed() bool {
	if ing.server == nil {
		return true
	}
	return ing.closed.Load()
}

// Close shuts down the server and listener. It is idempotent: the underlying
// lumberjack server panics on a second Close, so repeated calls (e.g. a
// cancellation watcher plus a deferred cleanup) are collapsed into one.
func (ing *TCPIngestor) Close() error {
	ing.closeOnce.Do(func() {
		// go-lumber's Server.Close() already closes the underlying listener, so
		// close the server XOR the listener — never both. Closing both stored a
		// spurious "use of closed network connection" (net.ErrClosed) and
		// discarded the real server error (URGENT-09).
		var err error
		if ing.server != nil {
			err = ing.server.Close()
		} else {
			err = ing.listener.Close()
		}
		// An already-closed listener is a benign no-op, not an operator-visible
		// error: map net.ErrClosed to nil.
		if errors.Is(err, net.ErrClosed) {
			err = nil
		}
		ing.closeErr = err
	})
	return ing.closeErr
}
