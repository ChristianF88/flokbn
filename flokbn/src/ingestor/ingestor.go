package ingestor

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
)

// The request record and its helpers live in the leaf package accesslog. The
// names below are aliases kept so that existing users of ingestor.Request and
// friends compile unchanged.
type (
	HTTPMethod = accesslog.HTTPMethod
	Request    = accesslog.Request
)

const (
	GET     = accesslog.GET
	POST    = accesslog.POST
	PUT     = accesslog.PUT
	DELETE  = accesslog.DELETE
	HEAD    = accesslog.HEAD
	OPTIONS = accesslog.OPTIONS
	PATCH   = accesslog.PATCH
	UNKNOWN = accesslog.UNKNOWN
)

func ParseMethod(m string) HTTPMethod { return accesslog.ParseMethod(m) }

// Uint32ToIPString converts uint32 back to IP string for output
func Uint32ToIPString(ip uint32) string { return accesslog.Uint32ToIPString(ip) }

// --- TCP Ingestor (Lumberjack v2, see lumberjack.go) ---

// Ingestor is the contract the live loop consumes. TCPIngestor is the
// lumberjack/TCP implementation; FLOKBN-037 will add a file-tailing one.
//
// IsClosed may report true while batches are still queued: after it does, a
// consumer must call ReadBatch until it returns nothing before giving up.
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
	ParseErrorsTotal     uint64 // events dropped: undecodable, no usable message, or unparseable line
	MalformedFieldsTotal uint64
	LastBatchAt          time.Time // zero until the first batch is read

	OpenConnections          int    // client connections open right now
	ConnectionsTotal         uint64 // connections accepted since start
	ConnectionsRejectedTotal uint64 // connections closed on accept (connection limit)
	ProtocolErrorsTotal      uint64 // connections dropped for a protocol or limit violation
}

var _ Ingestor = (*TCPIngestor)(nil)

// Options configures a TCPIngestor. The zero value is usable.
type Options struct {
	// ReadTimeout bounds how long a client may take to deliver one batch
	// once it has announced it, and how long an ack write may block.
	// <= 0 selects DefaultReadTimeout.
	ReadTimeout time.Duration
	// Limits bounds peer-driven allocations; zero fields select defaults.
	Limits Limits
	// TLS, when non-nil, makes the listener speak TLS (set ClientAuth and
	// ClientCAs on it for mutual TLS).
	TLS *tls.Config
	// Logger receives connection lifecycle lines; nil selects slog.Default().
	Logger *slog.Logger
}

// DefaultReadTimeout is used when Options.ReadTimeout is unset.
const DefaultReadTimeout = 30 * time.Second

// eventQueueBatches is the capacity of the batch queue between the
// connection goroutines and ReadBatch. The queue is additionally bounded in
// bytes by Limits.MaxQueuedBytes.
const eventQueueBatches = 1000

type TCPIngestor struct {
	listener    net.Listener
	readTimeout time.Duration
	limits      Limits
	logger      *slog.Logger
	events      chan *eventBatch
	budget      *byteBudget

	lifeMu    sync.Mutex // guards server and closing
	server    *ljServer
	closing   bool
	started   atomic.Bool
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error

	conns           connCounters
	batchesTotal    atomic.Uint64
	requestsTotal   atomic.Uint64
	parseErrors     atomic.Uint64
	malformedFields atomic.Uint64
	lastBatchUnixNs atomic.Int64
}

// NewTCPIngestor listens on addr with default limits.
func NewTCPIngestor(addr string, readTimeout time.Duration) (*TCPIngestor, error) {
	return NewTCPIngestorWithOptions(addr, Options{ReadTimeout: readTimeout})
}

// NewTCPIngestorWithOptions listens on addr. Clients are not served until
// Accept is called.
func NewTCPIngestorWithOptions(addr string, opts Options) (*TCPIngestor, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	if opts.TLS != nil {
		ln = tls.NewListener(ln, opts.TLS)
	}
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = DefaultReadTimeout
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	limits := opts.Limits.normalized()
	return &TCPIngestor{
		listener:    ln,
		readTimeout: opts.ReadTimeout,
		limits:      limits,
		logger:      opts.Logger,
		events:      make(chan *eventBatch, eventQueueBatches),
		budget:      newByteBudget(limits.MaxQueuedBytes),
	}, nil
}

// Addr returns the listener address. Useful when listening on an ephemeral
// port (e.g. "127.0.0.1:0" in tests).
func (ing *TCPIngestor) Addr() net.Addr {
	return ing.listener.Addr()
}

// Accept starts serving Lumberjack clients on the listener. It returns
// immediately; it does NOT wait for a client. Stats().OpenConnections tells
// whether one is connected.
//
// A batch is acknowledged to its client once it is queued for ReadBatch, not
// once the live loop has processed it: the loop polls on its own cadence, so
// holding acks until then would throttle every shipper to one batch per
// iteration. Batches still queued when the process dies are lost.
func (ing *TCPIngestor) Accept() error {
	ing.lifeMu.Lock()
	defer ing.lifeMu.Unlock()
	if ing.closing {
		return errors.New("ingestor is closed")
	}
	if ing.server != nil {
		return errors.New("ingestor already accepting")
	}
	ing.server = newLJServer(ing.listener, ing.readTimeout, ing.limits, ing.logger,
		ing.events, ing.budget, &ing.conns)
	ing.server.start()
	ing.started.Store(true)
	return nil
}

// parseLine parses one access-log line (the "message" field of a lumberjack
// event) into out. malformed counts non-fatal field corruption (status/bytes
// kept as zero), mirroring the log-parser's malformed-field accounting.
func parseLine(msg string, out *Request) (malformed int, err error) {
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
	t, end, err := locateTimestamp(msg, spaceIdx)
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

// locateTimestamp finds and parses the bracketed timestamp of a log line.
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
func locateTimestamp(msg string, ipEnd int) (time.Time, int, error) {
	pos := ipEnd + 1
	for i := 0; i < 2 && pos >= 0; i++ {
		if sp := strings.IndexByte(msg[pos:], ' '); sp >= 0 {
			pos += sp + 1
		} else {
			pos = -1
		}
	}
	if pos >= 0 && pos < len(msg) && msg[pos] == '[' {
		if t, end, err := parseBracketTime(msg, pos); err == nil {
			return t, end, nil
		}
	}
	first := strings.IndexByte(msg[ipEnd:], '[')
	if first < 0 {
		return time.Time{}, 0, errors.New("invalid timestamp format")
	}
	return parseBracketTime(msg, ipEnd+first)
}

// parseBracketTime parses the timestamp whose opening '[' is at msg[open] and
// returns it with the index of the closing ']'.
func parseBracketTime(msg string, open int) (time.Time, int, error) {
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

// closeQuote returns the index of the closing quote of a quoted field whose
// content begins at contentStart, or -1 if there is no (unescaped) closing
// quote at/after contentStart. The fast path uses strings.IndexByte (SIMD on
// amd64); the escape-aware slow path runs only when a candidate closing quote
// is immediately preceded by a backslash, so clean lines never pay for it.
// Field content keeps its raw escape bytes - this fixes field ALIGNMENT, not
// unescaping - matching the static parser exactly.
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

// parseLineSafe parses a single line, recovering from any panic in parseLine
// so one malformed (untrusted) event can never crash the live-loop goroutine.
// A recovered panic is surfaced as an error so the caller counts it as a parse
// error and skips the event (never appended, never zero-valued into output).
func parseLineSafe(msg string, out *Request) (malformed int, err error) {
	defer func() {
		if r := recover(); r != nil {
			malformed = 0
			err = fmt.Errorf("parseLine panic: %v", r)
		}
	}()
	return parseLine(msg, out)
}

// ParseEventForTest parses a single raw log line through the live ingestor's
// parseLine and returns the resulting Request. It exists solely so the
// live<->static UserAgent parity test (logparser/parser_live_ua_parity_test.go)
// can drive the live parser from a package that ALSO compiles the static format
// - ingestor is a leaf package that logparser imports, so the parity test cannot
// live in ingestor (it would have to import logparser, an import cycle). This is
// a thin wrapper over the unexported parseLine and is not part of the live data
// path (ReadBatch uses parseLineSafe directly).
func ParseEventForTest(line string) (Request, error) {
	var req Request
	_, err := parseLine(line, &req)
	return req, err
}

// ReadBatch drains every queued batch without blocking and returns the
// requests parsed from them.
func (ing *TCPIngestor) ReadBatch() ([]Request, error) {
	var out []Request

	for {
		select {
		case batch, ok := <-ing.events:
			if !ok {
				return out, nil
			}
			ing.budget.release(batch.cost)
			ing.batchesTotal.Add(1)
			ing.lastBatchUnixNs.Store(time.Now().UnixNano())
			if batch.dropped > 0 {
				ing.parseErrors.Add(uint64(batch.dropped))
			}
			if out == nil {
				out = make([]Request, 0, len(batch.msgs))
			}
			for _, msg := range batch.msgs {
				var entry Request
				if malformed, err := parseLineSafe(msg, &entry); err == nil {
					if malformed > 0 {
						ing.malformedFields.Add(uint64(malformed))
					}
					ing.requestsTotal.Add(1)
					out = append(out, entry)
				} else {
					ing.parseErrors.Add(1)
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
		QueueDepth:               len(ing.events),
		BatchesTotal:             ing.batchesTotal.Load(),
		RequestsTotal:            ing.requestsTotal.Load(),
		ParseErrorsTotal:         ing.parseErrors.Load(),
		MalformedFieldsTotal:     ing.malformedFields.Load(),
		OpenConnections:          int(ing.conns.open.Load()),
		ConnectionsTotal:         ing.conns.accepted.Load(),
		ConnectionsRejectedTotal: ing.conns.rejected.Load(),
		ProtocolErrorsTotal:      ing.conns.protocolErrors.Load(),
	}
	if ns := ing.lastBatchUnixNs.Load(); ns != 0 {
		st.LastBatchAt = time.Unix(0, ns)
	}
	return st
}

// IsClosed reports whether the ingestor is not (or no longer) accepting
// clients: before Accept, and once Close has stopped every connection.
// Batches queued before the close stay readable through ReadBatch.
func (ing *TCPIngestor) IsClosed() bool {
	if !ing.started.Load() {
		return true
	}
	return ing.closed.Load()
}

// Close stops the listener and every open connection, then closes the batch
// queue. It is idempotent, so repeated calls (e.g. a cancellation watcher plus
// a deferred cleanup) are collapsed into one.
func (ing *TCPIngestor) Close() error {
	ing.closeOnce.Do(func() {
		ing.lifeMu.Lock()
		ing.closing = true
		srv := ing.server
		ing.lifeMu.Unlock()

		var err error
		if srv != nil {
			// close waits for every connection goroutine, so nothing can be
			// sent on events afterwards and closing it is safe.
			err = srv.close()
			ing.closed.Store(true)
			close(ing.events)
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
