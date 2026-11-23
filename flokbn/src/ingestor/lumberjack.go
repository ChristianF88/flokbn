package ingestor

// A small Lumberjack v2 server (the protocol Filebeat's Logstash output
// speaks) with hard resource limits.
//
// flokbn used github.com/elastic/go-lumber's server here. That reader sizes
// its allocations from fields the peer controls - the window count, the JSON
// payload length and the inflated size of a compressed frame - so the six
// bytes "2W\xff\xff\xff\xff" were enough to kill the process with an
// out-of-memory fatal error. This implementation checks every wire-supplied
// size against Limits BEFORE allocating, bounds the number of concurrent
// connections, and bounds the bytes held for batches that are being read or
// are waiting in the queue.
//
// Wire format (all integers big-endian):
//
//	window      '2' 'W' count:uint32
//	json event  '2' 'J' seq:uint32 len:uint32 payload[len]
//	compressed  '2' 'C' len:uint32 zlib(json event ...)[len]
//	ack         '2' 'A' seq:uint32            (server -> client)
//
// A client sends one window frame followed by count events, either as plain
// json frames or wrapped in compressed frames, then waits for an ack carrying
// count. An ack carrying 0 is a keepalive ("still working on it").

import (
	"bufio"
	"compress/flate"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ljVersion         byte = '2'
	ljFrameWindow     byte = 'W'
	ljFrameJSON       byte = 'J'
	ljFrameCompressed byte = 'C'
	ljFrameACK        byte = 'A'

	// ljJSONFrameOverhead is the size of a json frame without its payload:
	// version, type, sequence number, payload length.
	ljJSONFrameOverhead = 10

	// ljKeepalive is how often a client that is waiting for its ack is told
	// the batch is still in progress. Filebeat's default timeout is 30s.
	ljKeepalive = 3 * time.Second

	// ljPreallocEvents caps the up-front capacity of a batch's event slice.
	// The window count is peer-controlled, so it never sizes an allocation
	// directly; larger batches grow by append as real frames arrive.
	ljPreallocEvents = 4096

	// ljReadBuffer is the per-connection read buffer.
	ljReadBuffer = 32 << 10

	// stringHeaderBytes approximates the slice slot one queued message costs
	// on top of its bytes.
	stringHeaderBytes = 16
)

// Limits bounds what Lumberjack peers can make the ingestor allocate. The zero
// value of any field selects its default (see DefaultLimits).
type Limits struct {
	// MaxWindowEvents is the largest event count a window frame may announce.
	MaxWindowEvents int
	// MaxEventBytes is the largest JSON payload of a single event.
	MaxEventBytes int
	// MaxBatchBytes caps one window: the total size of its json frames after
	// inflation, and the size of any single compressed frame.
	MaxBatchBytes int64
	// MaxQueuedBytes caps the bytes held for batches that are being read or
	// are queued for the live loop. Peers are held back (not dropped) while
	// the budget is exhausted.
	MaxQueuedBytes int64
	// MaxConnections is the largest number of simultaneously open client
	// connections; further connections are closed on accept.
	MaxConnections int
}

// DefaultLimits returns the limits used when none are configured. They sit
// far above what Filebeat sends by default (bulk_max_size 2048, access-log
// events of a few hundred bytes to a few KiB) so legitimate shippers never
// reach them.
func DefaultLimits() Limits {
	return Limits{
		MaxWindowEvents: 1 << 16,
		MaxEventBytes:   1 << 20,
		MaxBatchBytes:   32 << 20,
		MaxQueuedBytes:  512 << 20,
		MaxConnections:  64,
	}
}

// normalized fills unset (zero or negative) fields with their defaults and
// keeps the queue budget large enough to admit one full batch.
func (l Limits) normalized() Limits {
	d := DefaultLimits()
	if l.MaxWindowEvents <= 0 {
		l.MaxWindowEvents = d.MaxWindowEvents
	}
	if l.MaxEventBytes <= 0 {
		l.MaxEventBytes = d.MaxEventBytes
	}
	if l.MaxBatchBytes <= 0 {
		l.MaxBatchBytes = d.MaxBatchBytes
	}
	if l.MaxQueuedBytes <= 0 {
		l.MaxQueuedBytes = d.MaxQueuedBytes
	}
	if l.MaxQueuedBytes < l.MaxBatchBytes {
		l.MaxQueuedBytes = l.MaxBatchBytes
	}
	if l.MaxConnections <= 0 {
		l.MaxConnections = d.MaxConnections
	}
	return l
}

// eventBatch is one acknowledged window, reduced to what flokbn reads from
// it: the "message" field (the raw access-log line) of every event.
type eventBatch struct {
	msgs []string
	// dropped counts events whose JSON did not decode to an object with a
	// string "message" (invalid JSON, a bare string/number/array, a
	// non-string message). They are reported as parse errors.
	dropped int
	// cost is what the batch holds against the queue budget.
	cost int64
}

// ljEvent is the only part of a Lumberjack event flokbn uses. Decoding into
// it (instead of a generic map) skips Filebeat's metadata without allocating,
// so a queued event never costs more memory than its wire bytes.
type ljEvent struct {
	Message string `json:"message"`
}

// add decodes one event payload into the batch. Frames are length-delimited,
// so an undecodable payload does not desynchronise the stream: the event is
// dropped (and counted), the connection is kept.
func (b *eventBatch) add(payload []byte) {
	var ev ljEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		b.dropped++
		return
	}
	b.msgs = append(b.msgs, ev.Message)
	b.cost += int64(len(ev.Message)) + stringHeaderBytes
}

// protocolError marks a peer that violated the protocol or a limit, as
// opposed to an ordinary disconnect or timeout.
type protocolError struct{ msg string }

func (e *protocolError) Error() string { return e.msg }

func protocolErrorf(format string, args ...any) error {
	return &protocolError{msg: fmt.Sprintf(format, args...)}
}

var errServerClosed = errors.New("ingestor closed")

// midFrame converts a clean EOF into io.ErrUnexpectedEOF: inside a window an
// EOF always means the peer went away mid-batch.
func midFrame(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// compressedReader exposes exactly the bytes of one compressed frame. It
// implements io.ByteReader so the inflater reads through the connection's
// buffer instead of allocating its own (and reading past the frame).
type compressedReader struct {
	r *bufio.Reader
	n int64 // bytes of the frame not yet consumed
}

func (c *compressedReader) Read(p []byte) (int, error) {
	if c.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > c.n {
		p = p[:c.n]
	}
	n, err := c.r.Read(p)
	c.n -= int64(n)
	return n, err
}

func (c *compressedReader) ReadByte() (byte, error) {
	if c.n <= 0 {
		return 0, io.EOF
	}
	b, err := c.r.ReadByte()
	if err == nil {
		c.n--
	}
	return b, err
}

// ljReader decodes the client side of one connection.
type ljReader struct {
	in     *bufio.Reader
	limits Limits
	buf    []byte        // scratch for one JSON payload, at most MaxEventBytes
	zr     io.ReadCloser // inflater, reused across compressed frames
	cr     compressedReader
}

func newLJReader(r io.Reader, limits Limits) *ljReader {
	return &ljReader{in: bufio.NewReaderSize(r, ljReadBuffer), limits: limits}
}

// readWindow reads a window frame and returns the announced event count. A
// clean io.EOF means the peer closed the connection between batches.
func (r *ljReader) readWindow() (uint32, error) {
	var hdr [6]byte
	if _, err := io.ReadFull(r.in, hdr[:]); err != nil {
		return 0, err
	}
	if hdr[0] != ljVersion || hdr[1] != ljFrameWindow {
		return 0, protocolErrorf("expected a Lumberjack v2 window frame, got %q", hdr[:2])
	}
	count := binary.BigEndian.Uint32(hdr[2:])
	if uint64(count) > uint64(r.limits.MaxWindowEvents) {
		return 0, protocolErrorf("window of %d events exceeds the limit of %d", count, r.limits.MaxWindowEvents)
	}
	return count, nil
}

// readBatch reads the count events that follow a window frame.
func (r *ljReader) readBatch(count uint32) (*eventBatch, error) {
	want := int(count)
	b := &eventBatch{msgs: make([]string, 0, min(want, ljPreallocEvents))}
	left := r.limits.MaxBatchBytes
	for seen := 0; seen < want; {
		var hdr [2]byte
		if _, err := io.ReadFull(r.in, hdr[:]); err != nil {
			return nil, midFrame(err)
		}
		if hdr[0] != ljVersion {
			return nil, protocolErrorf("unsupported frame version %q", hdr[:1])
		}
		switch hdr[1] {
		case ljFrameJSON:
			if err := r.readJSON(r.in, b, &left); err != nil {
				return nil, err
			}
			seen++
		case ljFrameCompressed:
			n, err := r.readCompressed(b, want-seen, &left)
			if err != nil {
				return nil, err
			}
			seen += n
		default:
			return nil, protocolErrorf("unknown frame type %q", hdr[1:])
		}
	}
	return b, nil
}

// readJSON reads one json frame body from in (the connection, or the inflated
// view of a compressed frame) and appends its message to b. left is the
// batch's remaining byte allowance; both it and MaxEventBytes are checked
// before the payload buffer is sized.
func (r *ljReader) readJSON(in io.Reader, b *eventBatch, left *int64) error {
	var hdr [8]byte // sequence number (unused), payload length
	if _, err := io.ReadFull(in, hdr[:]); err != nil {
		return midFrame(err)
	}
	size := binary.BigEndian.Uint32(hdr[4:])
	if uint64(size) > uint64(r.limits.MaxEventBytes) {
		return protocolErrorf("event of %d bytes exceeds the limit of %d", size, r.limits.MaxEventBytes)
	}
	need := int64(size) + ljJSONFrameOverhead
	if need > *left {
		return protocolErrorf("batch exceeds the limit of %d bytes", r.limits.MaxBatchBytes)
	}
	*left -= need

	if int(size) > cap(r.buf) {
		// Grow geometrically, never past the per-event limit.
		r.buf = make([]byte, min(max(int(size), 2*cap(r.buf), 4096), r.limits.MaxEventBytes))
	}
	buf := r.buf[:size]
	if _, err := io.ReadFull(in, buf); err != nil {
		return midFrame(err)
	}

	b.add(buf)
	return nil
}

// readCompressed reads one compressed frame holding up to want json frames
// and returns how many it held. Inflation is driven frame by frame through
// readJSON, so no more is inflated than the batch allowance admits - a zlib
// bomb fails the size checks long before its output is materialised.
func (r *ljReader) readCompressed(b *eventBatch, want int, left *int64) (int, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r.in, hdr[:]); err != nil {
		return 0, midFrame(err)
	}
	size := int64(binary.BigEndian.Uint32(hdr[:]))
	if size > r.limits.MaxBatchBytes {
		return 0, protocolErrorf("compressed frame of %d bytes exceeds the limit of %d", size, r.limits.MaxBatchBytes)
	}
	r.cr = compressedReader{r: r.in, n: size}

	var err error
	if r.zr == nil {
		r.zr, err = zlib.NewReader(&r.cr)
	} else {
		err = r.zr.(zlib.Resetter).Reset(&r.cr, nil)
	}
	if err != nil {
		r.zr = nil
		return 0, inflateError(err)
	}

	got := 0
	for got < want {
		var fh [2]byte
		if _, err := io.ReadFull(r.zr, fh[:]); err != nil {
			if err == io.EOF {
				break // end of this compressed frame; more frames may follow
			}
			return 0, inflateError(err)
		}
		if fh[0] != ljVersion || fh[1] != ljFrameJSON {
			return 0, protocolErrorf("unexpected frame %q inside a compressed frame", fh[:])
		}
		if err := r.readJSON(r.zr, b, left); err != nil {
			return 0, inflateError(err)
		}
		got++
	}
	if got == 0 {
		return 0, protocolErrorf("compressed frame without events")
	}
	// Skip what the inflater left unread (stream trailer, padding) so the
	// connection is positioned at the next frame.
	if r.cr.n > 0 {
		if _, err := r.in.Discard(int(r.cr.n)); err != nil {
			return 0, midFrame(err)
		}
	}
	return got, nil
}

// inflateError classifies corrupt compressed data as a protocol violation and
// passes everything else (timeouts, disconnects, limit errors) through.
func inflateError(err error) error {
	var corrupt flate.CorruptInputError
	if errors.As(err, &corrupt) || errors.Is(err, zlib.ErrHeader) ||
		errors.Is(err, zlib.ErrChecksum) || errors.Is(err, zlib.ErrDictionary) {
		return protocolErrorf("corrupt compressed frame: %v", err)
	}
	return midFrame(err)
}

// byteBudget is a counting limit on bytes, with wake-up for waiters.
type byteBudget struct {
	mu   sync.Mutex
	max  int64
	used int64
	wake chan struct{} // non-nil while someone waits; closed on release
}

func newByteBudget(max int64) *byteBudget { return &byteBudget{max: max} }

// tryAcquire takes n bytes if they fit. Otherwise it returns a channel that
// is closed the next time bytes are released. A request is always admitted
// when nothing is held, so an oversized n cannot wait forever.
func (b *byteBudget) tryAcquire(n int64) (bool, <-chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used == 0 || b.used+n <= b.max {
		b.used += n
		return true, nil
	}
	if b.wake == nil {
		b.wake = make(chan struct{})
	}
	return false, b.wake
}

func (b *byteBudget) release(n int64) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	b.used -= n
	if b.wake != nil {
		close(b.wake)
		b.wake = nil
	}
	b.mu.Unlock()
}

func (b *byteBudget) inUse() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// connCounters are the connection-level counters surfaced by Stats.
type connCounters struct {
	open           atomic.Int64
	accepted       atomic.Uint64
	rejected       atomic.Uint64
	protocolErrors atomic.Uint64
}

// logLimiter bounds per-connection log lines so a peer that connects in a
// loop cannot flood the log.
type logLimiter struct {
	mu          sync.Mutex
	windowStart time.Time
	lines       int
	suppressed  int
}

const (
	logLimitWindow = 10 * time.Second
	logLimitLines  = 20
)

// allow reports whether a line may be logged now and, if so, how many lines
// were suppressed since the last one that was.
func (l *logLimiter) allow(now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.windowStart) >= logLimitWindow {
		l.windowStart = now
		l.lines = 0
	}
	if l.lines >= logLimitLines {
		l.suppressed++
		return false, 0
	}
	l.lines++
	n := l.suppressed
	l.suppressed = 0
	return true, n
}

// ljServer accepts Lumberjack connections on a listener and delivers every
// fully read batch to out.
type ljServer struct {
	ln      net.Listener
	timeout time.Duration
	limits  Limits
	logger  *slog.Logger
	out     chan<- *eventBatch
	budget  *byteBudget
	stats   *connCounters
	logLim  logLimiter

	done chan struct{}
	wg   sync.WaitGroup

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool
}

func newLJServer(ln net.Listener, timeout time.Duration, limits Limits, logger *slog.Logger,
	out chan<- *eventBatch, budget *byteBudget, stats *connCounters) *ljServer {
	return &ljServer{
		ln:      ln,
		timeout: timeout,
		limits:  limits,
		logger:  logger,
		out:     out,
		budget:  budget,
		stats:   stats,
		done:    make(chan struct{}),
		conns:   make(map[net.Conn]struct{}),
	}
}

func (s *ljServer) start() {
	s.wg.Add(1)
	go s.acceptLoop()
}

// close stops accepting, closes every open connection and waits until all
// connection goroutines have returned. After it returns nothing is sent to
// out any more.
func (s *ljServer) close() error {
	err := s.ln.Close()
	close(s.done)
	s.mu.Lock()
	s.closing = true
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

func (s *ljServer) log(level slog.Level, msg string, args ...any) {
	ok, suppressed := s.logLim.allow(time.Now())
	if !ok {
		return
	}
	if suppressed > 0 {
		args = append(args, "suppressed_log_lines", suppressed)
	}
	s.logger.Log(context.Background(), level, msg, args...)
}

func (s *ljServer) acceptLoop() {
	defer s.wg.Done()
	var delay time.Duration
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient failure (e.g. out of file descriptors): back off and
			// keep serving instead of silently ending ingestion.
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay *= 2; delay > time.Second {
				delay = time.Second
			}
			s.log(slog.LevelWarn, "accepting ingest connection failed", "error", err.Error(), "retry_in", delay.String())
			select {
			case <-s.done:
				return
			case <-time.After(delay):
			}
			continue
		}
		delay = 0

		open, ok := s.track(c)
		if !ok {
			select {
			case <-s.done:
				// Accepted while shutting down: not a limit rejection.
				c.Close()
				return
			default:
			}
			// Count and log before closing, so whoever observes the close
			// also observes why.
			s.stats.rejected.Add(1)
			s.log(slog.LevelWarn, "ingest connection rejected: connection limit reached",
				"remote", c.RemoteAddr().String(), "max_connections", s.limits.MaxConnections)
			c.Close()
			continue
		}
		s.stats.accepted.Add(1)
		s.wg.Add(1)
		go s.serve(c, open)
	}
}

// track registers c unless the server is closing or full. It returns the
// number of open connections including c. The closing check shares the lock
// with close's sweep over conns, so a connection is either swept there or
// refused here - never left open after close returns.
func (s *ljServer) track(c net.Conn) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || len(s.conns) >= s.limits.MaxConnections {
		return 0, false
	}
	s.conns[c] = struct{}{}
	s.stats.open.Store(int64(len(s.conns)))
	return len(s.conns), true
}

func (s *ljServer) untrack(c net.Conn) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
	s.stats.open.Store(int64(len(s.conns)))
	return len(s.conns)
}

func (s *ljServer) serve(c net.Conn, open int) {
	defer s.wg.Done()
	remote := c.RemoteAddr().String()
	s.log(slog.LevelInfo, "Filebeat connected", "remote", remote, "open_connections", open)

	err := s.handle(c)
	var perr *protocolError
	if errors.As(err, &perr) {
		s.stats.protocolErrors.Add(1)
	}
	open = s.untrack(c)
	c.Close()

	switch {
	case perr != nil:
		s.log(slog.LevelWarn, "Filebeat disconnected: protocol violation",
			"remote", remote, "error", err.Error(), "open_connections", open)
	case err == nil || err == io.EOF:
		s.log(slog.LevelInfo, "Filebeat disconnected", "remote", remote, "open_connections", open)
	case errors.Is(err, errServerClosed):
		s.log(slog.LevelInfo, "Filebeat disconnected: ingestor closing", "remote", remote, "open_connections", open)
	default:
		s.log(slog.LevelInfo, "Filebeat disconnected", "remote", remote, "reason", err.Error(), "open_connections", open)
	}
}

// handle runs the read-queue-acknowledge cycle of one connection until the
// peer leaves, misbehaves, or the server closes.
func (s *ljServer) handle(c net.Conn) error {
	if tc, ok := c.(*tls.Conn); ok {
		// Bound the handshake: without a deadline a silent peer would hold a
		// connection slot in a half-open TLS state forever.
		if err := c.SetDeadline(time.Now().Add(s.timeout)); err != nil {
			return err
		}
		if err := tc.Handshake(); err != nil {
			return fmt.Errorf("TLS handshake: %w", err)
		}
		if err := c.SetDeadline(time.Time{}); err != nil {
			return err
		}
	}

	r := newLJReader(c, s.limits)
	for {
		// Between batches a shipper may stay silent for as long as its log is
		// quiet, so the wait for the next window has no deadline.
		if err := c.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
		count, err := r.readWindow()
		if err != nil {
			return s.shutdownOr(err)
		}
		if count == 0 {
			continue
		}

		// Reserve a full batch before reading it; trimmed to the real cost
		// once the batch is decoded.
		if err := s.reserve(c, s.limits.MaxBatchBytes); err != nil {
			return err
		}
		if err := c.SetReadDeadline(time.Now().Add(s.timeout)); err != nil {
			s.budget.release(s.limits.MaxBatchBytes)
			return err
		}
		b, err := r.readBatch(count)
		if err != nil {
			s.budget.release(s.limits.MaxBatchBytes)
			return s.shutdownOr(err)
		}
		if b.cost > s.limits.MaxBatchBytes {
			b.cost = s.limits.MaxBatchBytes
		}
		s.budget.release(s.limits.MaxBatchBytes - b.cost)

		if err := s.enqueue(c, b); err != nil {
			s.budget.release(b.cost)
			return err
		}
		if err := s.writeACK(c, count); err != nil {
			return s.shutdownOr(err)
		}
	}
}

// shutdownOr reports errServerClosed instead of the I/O error that closing
// the connection during shutdown provokes.
func (s *ljServer) shutdownOr(err error) error {
	select {
	case <-s.done:
		return errServerClosed
	default:
		return err
	}
}

// reserve blocks until n bytes of queue budget are available, keeping the
// client's ack timer alive meanwhile.
func (s *ljServer) reserve(c net.Conn, n int64) error {
	for {
		ok, wake := s.budget.tryAcquire(n)
		if ok {
			return nil
		}
		t := time.NewTimer(ljKeepalive)
		select {
		case <-wake:
			t.Stop()
		case <-s.done:
			t.Stop()
			return errServerClosed
		case <-t.C:
			if err := s.writeACK(c, 0); err != nil {
				return err
			}
		}
	}
}

// enqueue hands b to the live loop, keeping the client's ack timer alive
// while the queue is full.
func (s *ljServer) enqueue(c net.Conn, b *eventBatch) error {
	select {
	case s.out <- b:
		return nil
	default:
	}
	t := time.NewTicker(ljKeepalive)
	defer t.Stop()
	for {
		select {
		case s.out <- b:
			return nil
		case <-s.done:
			return errServerClosed
		case <-t.C:
			if err := s.writeACK(c, 0); err != nil {
				return err
			}
		}
	}
}

func (s *ljServer) writeACK(c net.Conn, seq uint32) error {
	var buf [6]byte
	buf[0] = ljVersion
	buf[1] = ljFrameACK
	binary.BigEndian.PutUint32(buf[2:], seq)
	if err := c.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		return err
	}
	_, err := c.Write(buf[:])
	return err
}
