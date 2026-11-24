package ingestor

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/logparser"
)

// --- TCP Ingestor (Lumberjack v2, see lumberjack.go) ---

// Ingestor is the contract the live loop consumes. TCPIngestor is the
// lumberjack/TCP implementation; FLOKBN-037 will add a file-tailing one.
//
// IsClosed may report true while batches are still queued: after it does, a
// consumer must call ReadBatch until it returns nothing before giving up.
type Ingestor interface {
	Accept() error
	ReadBatch() ([]accesslog.Request, error)
	IsClosed() bool
	Close() error
	Stats() IngestStats
}

// IngestStats is a point-in-time view of the ingestor's counters.
type IngestStats struct {
	QueueDepth           int
	BatchesTotal         uint64
	RequestsTotal        uint64
	ParseErrorsTotal     uint64    // events dropped: undecodable, no usable message, or unparseable line
	MalformedFieldsTotal uint64    // status or bytes fields that are not a number, on any parsed line
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
	// LogFormat is the logparser format string each event's message is parsed
	// with. Empty selects logparser.DefaultLiveLogFormat (combined log format,
	// client IP in the first field).
	LogFormat string
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
	parser      *logparser.LineParser
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
	lastBatchUnixNs atomic.Int64
}

// NewTCPIngestor listens on addr with default limits and the default live log
// format.
func NewTCPIngestor(addr string, readTimeout time.Duration) (*TCPIngestor, error) {
	return NewTCPIngestorWithOptions(addr, Options{ReadTimeout: readTimeout})
}

// NewTCPIngestorWithOptions listens on addr. Clients are not served until
// Accept is called. An invalid opts.LogFormat is reported before the address
// is bound.
func NewTCPIngestorWithOptions(addr string, opts Options) (*TCPIngestor, error) {
	parser, err := newLineParser(opts.LogFormat)
	if err != nil {
		return nil, err
	}
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
		parser:      parser,
		readTimeout: opts.ReadTimeout,
		limits:      limits,
		logger:      opts.Logger,
		events:      make(chan *eventBatch, eventQueueBatches),
		budget:      newByteBudget(limits.MaxQueuedBytes),
	}, nil
}

// newLineParser compiles the log format of an ingestor; empty selects the
// default live format.
func newLineParser(format string) (*logparser.LineParser, error) {
	if format == "" {
		format = logparser.DefaultLiveLogFormat
	}
	parser, err := logparser.NewLineParser(format)
	if err != nil {
		return nil, fmt.Errorf("invalid log format %q: %w", format, err)
	}
	return parser, nil
}

// LogFormat returns the format string events are parsed with.
func (ing *TCPIngestor) LogFormat() string {
	return ing.parser.Format()
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

// parseLine parses one access-log line (the "message" field of a Lumberjack
// event) into out with the configured log format. The line comes from the
// network, so a panic in the parser is turned into an error: one event can
// then never take down the live loop, it is counted as a parse error and
// skipped like any other line that does not parse.
func (ing *TCPIngestor) parseLine(msg string, out *accesslog.Request) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("log parser panic: %v", r)
		}
	}()
	return ing.parser.ParseLine(msg, out)
}

// ReadBatch drains every queued batch without blocking and returns the
// requests parsed from them.
func (ing *TCPIngestor) ReadBatch() ([]accesslog.Request, error) {
	var out []accesslog.Request

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
				out = make([]accesslog.Request, 0, len(batch.msgs))
			}
			for _, msg := range batch.msgs {
				var entry accesslog.Request
				if err := ing.parseLine(msg, &entry); err == nil {
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
	parsed := ing.parser.Stats()
	st := IngestStats{
		QueueDepth:               len(ing.events),
		BatchesTotal:             ing.batchesTotal.Load(),
		RequestsTotal:            ing.requestsTotal.Load(),
		ParseErrorsTotal:         ing.parseErrors.Load(),
		MalformedFieldsTotal:     parsed.MalformedStatus + parsed.MalformedBytes,
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
