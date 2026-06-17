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
		return 0, errors.New("IPv6 not supported (IPv4-only)")
	}
	ip := net.ParseIP(ipTok)
	if ip == nil {
		return 0, errors.New("invalid IP")
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, errors.New("IPv6 not supported (IPv4-only)")
	}
	out.IP = ip
	out.IPUint32 = binary.BigEndian.Uint32(ip4)

	// 2. Extract timestamp
	start := strings.IndexByte(msg, '[')
	end := strings.IndexByte(msg, ']')
	if start < 0 || end <= start {
		return 0, errors.New("invalid timestamp format")
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", msg[start+1:end])
	if err != nil {
		return 0, err
	}
	out.Timestamp = t

	// 3. Request line (after first quote)
	start = strings.IndexByte(msg[end:], '"')
	if start == -1 {
		return 0, errors.New("missing request start quote")
	}
	start += end + 1
	end = strings.IndexByte(msg[start:], '"')
	if end == -1 {
		return 0, errors.New("missing request end quote")
	}
	end += start
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
		if status, err := strconv.Atoi(fields[0]); err == nil {
			out.Status = uint16(status)
		} else {
			malformed++
		}
		if bytesSent, err := strconv.Atoi(fields[1]); err == nil {
			out.Bytes = uint32(bytesSent)
		} else {
			malformed++
		}
	}

	// 5. User-Agent (quoted string after 4th quote)
	q := 0
	start = 0
	for i := 0; i < len(msg); i++ {
		if msg[i] == '"' {
			q++
			if q == 5 {
				start = i + 1
			} else if q == 6 {
				out.UserAgent = msg[start:i]
				break
			}
		}
	}

	return malformed, nil
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
		if ing.server != nil {
			ing.server.Close()
		}
		ing.closeErr = ing.listener.Close()
	})
	return ing.closeErr
}
