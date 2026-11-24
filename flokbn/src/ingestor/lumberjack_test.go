package ingestor

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	v2 "github.com/elastic/go-lumber/client/v2"

	"github.com/ChristianF88/flokbn/accesslog"
)

// --- wire helpers ---------------------------------------------------------

func windowFrame(n uint32) []byte {
	b := []byte{'2', 'W', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[2:], n)
	return b
}

func jsonFrameHeader(seq, size uint32) []byte {
	b := []byte{'2', 'J', 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[2:], seq)
	binary.BigEndian.PutUint32(b[6:], size)
	return b
}

func jsonFrame(seq uint32, payload string) []byte {
	return append(jsonFrameHeader(seq, uint32(len(payload))), payload...)
}

func deflate(t testing.TB, inner []byte) []byte {
	t.Helper()
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	if _, err := w.Write(inner); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return z.Bytes()
}

func compressedFrameRaw(deflated []byte) []byte {
	b := []byte{'2', 'C', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[2:], uint32(len(deflated)))
	return append(b, deflated...)
}

func compressedFrame(t testing.TB, inner []byte) []byte {
	return compressedFrameRaw(deflate(t, inner))
}

func messageJSON(line string) string {
	return fmt.Sprintf(`{"@timestamp":"2024-03-12T15:04:05Z","host":{"name":"web1"},"message":%q,"log":{"offset":1}}`, line)
}

// --- test plumbing --------------------------------------------------------

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startIngestor starts an accepting ingestor on an ephemeral loopback port
// and returns it with its captured log output.
func startIngestor(t testing.TB, opts Options) (*TCPIngestor, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(logs, nil))
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = 2 * time.Second
	}
	ing, err := NewTCPIngestorWithOptions("127.0.0.1:0", opts)
	if err != nil {
		t.Fatalf("NewTCPIngestorWithOptions: %v", err)
	}
	t.Cleanup(func() { ing.Close() })
	if err := ing.Accept(); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	return ing, logs
}

func dialRaw(t testing.TB, ing *TCPIngestor) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", ing.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// expectClosed asserts the server closes c (EOF or reset) without sending an
// ack first.
func expectClosed(t testing.TB, c net.Conn) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var buf [6]byte
	n, err := io.ReadFull(c, buf[:])
	if err == nil {
		t.Fatalf("server answered %q, want the connection closed", buf[:n])
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("server kept the connection open (read timed out), want it closed")
	}
}

// expectACK reads one ack frame and asserts its sequence number, skipping
// keepalives (ack 0).
func expectACK(t testing.TB, c net.Conn, want uint32) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	for {
		var buf [6]byte
		if _, err := io.ReadFull(c, buf[:]); err != nil {
			t.Fatalf("reading ack: %v", err)
		}
		if buf[0] != '2' || buf[1] != 'A' {
			t.Fatalf("got frame %q, want an ack", buf[:2])
		}
		got := binary.BigEndian.Uint32(buf[2:])
		if got == 0 && want != 0 {
			continue
		}
		if got != want {
			t.Fatalf("ack = %d, want %d", got, want)
		}
		return
	}
}

// allocatedDuring returns the bytes allocated process-wide while f runs.
func allocatedDuring(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func readAll(t *testing.T, ing *TCPIngestor, want int) []accesslog.Request {
	t.Helper()
	var got []accesslog.Request
	waitFor(t, 5*time.Second, fmt.Sprintf("%d requests", want), func() bool {
		batch, err := ing.ReadBatch()
		if err != nil {
			t.Fatalf("ReadBatch: %v", err)
		}
		got = append(got, batch...)
		return len(got) >= want
	})
	return got
}

const testLine = `203.0.113.7 - - [12/Mar/2024:15:04:05 -0700] "GET /ok HTTP/1.1" 200 5 "-" "UA"`

// --- A1: hostile input ----------------------------------------------------

// The reproduced crash: six bytes announcing a 4-billion-event window made
// go-lumber allocate the event slice up front and the runtime died with
// "fatal error: runtime: out of memory". The window is now rejected before
// anything is sized from it.
func TestLumberjack_HugeWindowIsRejectedWithoutAllocating(t *testing.T) {
	ing, _ := startIngestor(t, Options{})
	c := dialRaw(t, ing)

	allocated := allocatedDuring(func() {
		if _, err := c.Write([]byte("2W\xff\xff\xff\xff")); err != nil {
			t.Fatalf("write: %v", err)
		}
		expectClosed(t, c)
	})
	if allocated > 4<<20 {
		t.Errorf("allocated %d bytes handling a 6-byte header, want well under 4 MiB", allocated)
	}
	waitFor(t, 5*time.Second, "protocol error to be counted", func() bool {
		return ing.Stats().ProtocolErrorsTotal == 1
	})

	// The process is alive and a well-behaved shipper is still served.
	client, err := v2.SyncDial(ing.Addr().String())
	if err != nil {
		t.Fatalf("SyncDial after attack: %v", err)
	}
	defer client.Close()
	if _, err := client.Send([]interface{}{map[string]interface{}{"message": testLine}}); err != nil {
		t.Fatalf("Send after attack: %v", err)
	}
	if got := readAll(t, ing, 1); got[0].URI != "/ok" {
		t.Errorf("request after attack = %+v, want URI /ok", got[0])
	}
}

// The window size just above the limit is refused, the limit itself is not.
func TestLumberjack_WindowLimitBoundary(t *testing.T) {
	ing, _ := startIngestor(t, Options{Limits: Limits{MaxWindowEvents: 3}})

	over := dialRaw(t, ing)
	if _, err := over.Write(windowFrame(4)); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, over)

	ok := dialRaw(t, ing)
	msg := windowFrame(3)
	for i := uint32(1); i <= 3; i++ {
		msg = append(msg, jsonFrame(i, messageJSON(testLine))...)
	}
	if _, err := ok.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectACK(t, ok, 3)
	if got := readAll(t, ing, 3); len(got) != 3 {
		t.Errorf("got %d requests, want 3", len(got))
	}
}

// A json frame that announces a 4 GiB payload used to size a buffer from the
// header. It is refused before the buffer exists.
func TestLumberjack_OversizedJSONFrameIsRejectedWithoutAllocating(t *testing.T) {
	ing, _ := startIngestor(t, Options{})
	c := dialRaw(t, ing)

	allocated := allocatedDuring(func() {
		msg := append(windowFrame(1), jsonFrameHeader(1, 0xffffffff)...)
		if _, err := c.Write(msg); err != nil {
			t.Fatalf("write: %v", err)
		}
		expectClosed(t, c)
	})
	if allocated > 4<<20 {
		t.Errorf("allocated %d bytes handling an oversized frame header, want well under 4 MiB", allocated)
	}
	waitFor(t, 5*time.Second, "protocol error to be counted", func() bool {
		return ing.Stats().ProtocolErrorsTotal == 1
	})
	if got := ing.budget.inUse(); got != 0 {
		t.Errorf("queue budget in use = %d after a rejected batch, want 0", got)
	}
}

// One byte over the per-event limit is refused, the limit itself is not.
func TestLumberjack_EventLimitBoundary(t *testing.T) {
	payload := messageJSON(testLine)
	ing, _ := startIngestor(t, Options{Limits: Limits{MaxEventBytes: len(payload)}})

	ok := dialRaw(t, ing)
	if _, err := ok.Write(append(windowFrame(1), jsonFrame(1, payload)...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectACK(t, ok, 1)

	over := dialRaw(t, ing)
	if _, err := over.Write(append(windowFrame(1), jsonFrame(1, payload+" ")...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, over)
}

// A compressed frame of a few KiB that inflates to 64 MiB of events. The
// inflated stream is consumed frame by frame against the batch allowance, so
// memory stays near the configured limit instead of following the bomb.
func TestLumberjack_ZlibBombIsRejectedWithoutInflatingIt(t *testing.T) {
	const (
		eventBytes = 64 << 10
		events     = 1000 // 64 MiB inflated
		batchLimit = 256 << 10
	)
	// Build the bomb as a stream so the test itself never holds 64 MiB.
	payload := `{"message":"` + strings.Repeat("a", eventBytes-14) + `"}`
	if len(payload) != eventBytes {
		t.Fatalf("payload is %d bytes, want %d", len(payload), eventBytes)
	}
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	for i := uint32(1); i <= events; i++ {
		if _, err := zw.Write(jsonFrame(i, payload)); err != nil {
			t.Fatalf("zlib write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	bomb := append(windowFrame(events), compressedFrameRaw(z.Bytes())...)
	if len(bomb) > 1<<20 {
		t.Fatalf("bomb is %d bytes on the wire, expected it to compress below 1 MiB", len(bomb))
	}

	ing, _ := startIngestor(t, Options{Limits: Limits{
		MaxEventBytes: eventBytes,
		MaxBatchBytes: batchLimit,
	}})
	c := dialRaw(t, ing)

	allocated := allocatedDuring(func() {
		// The server may close mid-write; that is the expected outcome.
		_, _ = c.Write(bomb)
		expectClosed(t, c)
	})
	// Bounded by the batch limit (messages kept) plus the event scratch
	// buffer, the read buffer and the inflater - nowhere near 64 MiB.
	if allocated > 4<<20 {
		t.Errorf("allocated %d bytes handling a zlib bomb, want under 4 MiB (batch limit %d)", allocated, batchLimit)
	}
	waitFor(t, 5*time.Second, "protocol error to be counted", func() bool {
		return ing.Stats().ProtocolErrorsTotal == 1
	})
	if st := ing.Stats(); st.QueueDepth != 0 {
		t.Errorf("QueueDepth = %d, want 0 (a rejected batch is never queued)", st.QueueDepth)
	}
	if got := ing.budget.inUse(); got != 0 {
		t.Errorf("queue budget in use = %d after a rejected batch, want 0", got)
	}
}

// The same bomb shape against the DEFAULT limits: a compressed frame whose
// inflated content announces a 4 GiB event.
func TestLumberjack_CompressedOversizedEventIsRejected(t *testing.T) {
	ing, _ := startIngestor(t, Options{})
	c := dialRaw(t, ing)
	msg := append(windowFrame(1), compressedFrame(t, jsonFrameHeader(1, 0xfffffff0))...)
	allocated := allocatedDuring(func() {
		if _, err := c.Write(msg); err != nil {
			t.Fatalf("write: %v", err)
		}
		expectClosed(t, c)
	})
	if allocated > 4<<20 {
		t.Errorf("allocated %d bytes, want well under 4 MiB", allocated)
	}
}

// A compressed frame that announces more bytes than a whole batch may hold
// is refused from its 4-byte length alone.
func TestLumberjack_OversizedCompressedFrameIsRejected(t *testing.T) {
	ing, _ := startIngestor(t, Options{})
	c := dialRaw(t, ing)
	msg := append(windowFrame(1), '2', 'C', 0xff, 0xff, 0xff, 0xff)
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, c)
}

func TestLumberjack_ProtocolViolationsCloseTheConnection(t *testing.T) {
	cases := map[string][]byte{
		"not lumberjack":          []byte("GET / HTTP/1.1\r\n\r\n"),
		"v1 window":               []byte("1W\x00\x00\x00\x01"),
		"wrong first frame":       []byte("2J\x00\x00\x00\x01"),
		"unknown frame in window": append(windowFrame(1), '2', 'X'),
		"bad version in window":   append(windowFrame(1), '9', 'J'),
		"corrupt zlib":            append(windowFrame(1), compressedFrameRaw([]byte("this is not zlib data"))...),
		"empty compressed frame":  append(windowFrame(1), compressedFrame(t, nil)...),
		"nested compressed frame": append(windowFrame(1), compressedFrame(t, compressedFrame(t, jsonFrame(1, messageJSON(testLine))))...),
	}
	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			ing, _ := startIngestor(t, Options{})
			c := dialRaw(t, ing)
			if _, err := c.Write(msg); err != nil {
				t.Fatalf("write: %v", err)
			}
			expectClosed(t, c)
			waitFor(t, 5*time.Second, "protocol error to be counted", func() bool {
				return ing.Stats().ProtocolErrorsTotal == 1
			})
		})
	}
}

// A peer that announces a batch and then stalls is dropped after the read
// timeout and gives its queue reservation back.
func TestLumberjack_StalledBatchTimesOutAndReleasesBudget(t *testing.T) {
	ing, _ := startIngestor(t, Options{ReadTimeout: 100 * time.Millisecond})
	c := dialRaw(t, ing)
	if _, err := c.Write(windowFrame(5)); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, c)
	waitFor(t, 5*time.Second, "reservation to be released", func() bool {
		return ing.budget.inUse() == 0 && ing.Stats().OpenConnections == 0
	})
	if got := ing.Stats().ProtocolErrorsTotal; got != 0 {
		t.Errorf("ProtocolErrorsTotal = %d, want 0 (a timeout is not a protocol violation)", got)
	}
}

// --- A1: well-formed input keeps working ----------------------------------

func TestLumberjack_GoLumberClientCompressedAndPlain(t *testing.T) {
	for name, level := range map[string]int{"compressed": 3, "plain": 0} {
		t.Run(name, func(t *testing.T) {
			ing, _ := startIngestor(t, Options{})
			client, err := v2.SyncDial(ing.Addr().String(), v2.CompressionLevel(level))
			if err != nil {
				t.Fatalf("SyncDial: %v", err)
			}
			defer client.Close()

			const n = 500
			now := time.Now()
			events := make([]interface{}, n)
			for i := range events {
				events[i] = map[string]interface{}{
					"message":    apacheLine(fmt.Sprintf("198.51.%d.%d", i/256, i%256), now, fmt.Sprintf("/p/%d", i)),
					"@timestamp": now.Format(time.RFC3339),
					"host":       map[string]interface{}{"name": "web1"},
				}
			}
			seq, err := client.Send(events)
			if err != nil {
				t.Fatalf("Send: %v", err)
			}
			if seq != n {
				t.Fatalf("acked %d events, want %d", seq, n)
			}
			got := readAll(t, ing, n)
			if len(got) != n {
				t.Fatalf("got %d requests, want %d", len(got), n)
			}
			for i, r := range got {
				if want := fmt.Sprintf("/p/%d", i); r.URI != want {
					t.Fatalf("request %d URI = %q, want %q (order must be preserved)", i, r.URI, want)
				}
			}
			if st := ing.Stats(); st.ParseErrorsTotal != 0 || st.ProtocolErrorsTotal != 0 {
				t.Errorf("stats = %+v, want no parse or protocol errors", st)
			}
		})
	}
}

// A window may mix plain frames and several compressed frames; a second
// window on the same connection reuses the inflater.
func TestLumberjack_MixedFramesAndInflaterReuse(t *testing.T) {
	ing, _ := startIngestor(t, Options{})
	c := dialRaw(t, ing)

	line := func(i int) string {
		return fmt.Sprintf(`203.0.113.%d - - [12/Mar/2024:15:04:05 -0700] "GET /m/%d HTTP/1.1" 200 5 "-" "UA"`, i, i)
	}
	msg := windowFrame(5)
	msg = append(msg, jsonFrame(1, messageJSON(line(1)))...)
	msg = append(msg, compressedFrame(t, append(jsonFrame(2, messageJSON(line(2))), jsonFrame(3, messageJSON(line(3)))...))...)
	msg = append(msg, compressedFrame(t, jsonFrame(4, messageJSON(line(4))))...)
	msg = append(msg, jsonFrame(5, messageJSON(line(5)))...)
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectACK(t, c, 5)

	// Empty window: nothing to ack, connection stays usable.
	second := append(windowFrame(0), windowFrame(1)...)
	second = append(second, compressedFrame(t, jsonFrame(1, messageJSON(line(6))))...)
	if _, err := c.Write(second); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectACK(t, c, 1)

	got := readAll(t, ing, 6)
	for i, r := range got {
		if want := fmt.Sprintf("/m/%d", i+1); r.URI != want {
			t.Errorf("request %d URI = %q, want %q", i, r.URI, want)
		}
	}
}

// An event whose payload is not usable JSON is dropped and counted, but the
// rest of the batch is kept and acknowledged: frames are length-delimited,
// so one bad event does not justify making the shipper resend forever.
func TestLumberjack_UndecodableEventsAreCountedNotFatal(t *testing.T) {
	ing, _ := startIngestor(t, Options{})
	c := dialRaw(t, ing)

	msg := windowFrame(6)
	msg = append(msg, jsonFrame(1, `{"message":`)...)       // truncated JSON
	msg = append(msg, jsonFrame(2, `"just a string"`)...)   // not an object
	msg = append(msg, jsonFrame(3, `[1,2,3]`)...)           // not an object
	msg = append(msg, jsonFrame(4, `{"message":42}`)...)    // message is not a string
	msg = append(msg, jsonFrame(5, `{"other":"field"}`)...) // no message
	msg = append(msg, jsonFrame(6, messageJSON(testLine))...)
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectACK(t, c, 6)

	got := readAll(t, ing, 1)
	if len(got) != 1 || got[0].URI != "/ok" {
		t.Fatalf("got %+v, want the one valid request", got)
	}
	st := ing.Stats()
	if st.ParseErrorsTotal != 5 {
		t.Errorf("ParseErrorsTotal = %d, want 5 (every unusable event counted once)", st.ParseErrorsTotal)
	}
	if st.RequestsTotal != 1 {
		t.Errorf("RequestsTotal = %d, want 1", st.RequestsTotal)
	}
	if st.ProtocolErrorsTotal != 0 {
		t.Errorf("ProtocolErrorsTotal = %d, want 0", st.ProtocolErrorsTotal)
	}
}

// --- A1: connection limit, A3: connection tracking -------------------------

func TestLumberjack_ConnectionLimit(t *testing.T) {
	ing, logs := startIngestor(t, Options{Limits: Limits{MaxConnections: 2}})

	c1 := dialRaw(t, ing)
	c2 := dialRaw(t, ing)
	waitFor(t, 5*time.Second, "two open connections", func() bool {
		return ing.Stats().OpenConnections == 2
	})

	c3 := dialRaw(t, ing)
	expectClosed(t, c3)
	st := ing.Stats()
	if st.ConnectionsRejectedTotal != 1 {
		t.Errorf("ConnectionsRejectedTotal = %d, want 1", st.ConnectionsRejectedTotal)
	}
	if st.OpenConnections != 2 {
		t.Errorf("OpenConnections = %d, want 2 (rejected connection must not count)", st.OpenConnections)
	}
	if !strings.Contains(logs.String(), "connection limit reached") {
		t.Errorf("log does not mention the connection limit:\n%s", logs.String())
	}

	// A slot frees up when a client leaves.
	c1.Close()
	waitFor(t, 5*time.Second, "slot to free up", func() bool {
		return ing.Stats().OpenConnections == 1
	})
	c4 := dialRaw(t, ing)
	if _, err := c4.Write(append(windowFrame(1), jsonFrame(1, messageJSON(testLine))...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectACK(t, c4, 1)
	_ = c2
}

// Accept only starts the server. OpenConnections must follow real clients:
// zero before one connects, zero again after it leaves, with a log line for
// each transition.
func TestTCPIngestor_OpenConnectionsFollowsClients(t *testing.T) {
	ing, logs := startIngestor(t, Options{})

	if got := ing.Stats().OpenConnections; got != 0 {
		t.Fatalf("OpenConnections = %d right after Accept, want 0 (nobody connected yet)", got)
	}
	if strings.Contains(logs.String(), "Filebeat connected") {
		t.Fatalf("logged a connection before any client connected:\n%s", logs.String())
	}

	c := dialRaw(t, ing)
	waitFor(t, 5*time.Second, "connection to be counted", func() bool {
		return ing.Stats().OpenConnections == 1
	})
	waitFor(t, 5*time.Second, "connect log line", func() bool {
		return strings.Contains(logs.String(), "Filebeat connected")
	})
	if ing.IsClosed() {
		t.Error("IsClosed() = true while serving")
	}

	c.Close()
	waitFor(t, 5*time.Second, "disconnect to be counted", func() bool {
		return ing.Stats().OpenConnections == 0
	})
	waitFor(t, 5*time.Second, "disconnect log line", func() bool {
		return strings.Contains(logs.String(), "Filebeat disconnected")
	})
	if got := ing.Stats().ConnectionsTotal; got != 1 {
		t.Errorf("ConnectionsTotal = %d, want 1", got)
	}
	if ing.IsClosed() {
		t.Error("IsClosed() = true after a client left, want false (still listening)")
	}
}

func TestTCPIngestor_CloseDropsOpenConnections(t *testing.T) {
	ing, _ := startIngestor(t, Options{})
	c := dialRaw(t, ing)
	waitFor(t, 5*time.Second, "connection to be counted", func() bool {
		return ing.Stats().OpenConnections == 1
	})
	if err := ing.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := ing.Stats().OpenConnections; got != 0 {
		t.Errorf("OpenConnections = %d after Close, want 0", got)
	}
	expectClosed(t, c)
	if err := ing.Accept(); err == nil {
		t.Error("Accept after Close succeeded, want an error")
	}
}

// --- queue budget -----------------------------------------------------------

// When the live loop does not drain, shippers are held back by a withheld ack
// (and kept alive) once the byte budget is used up - the queue cannot grow
// without bound - and they resume when the loop reads.
func TestLumberjack_QueueBudgetHoldsBackAndResumes(t *testing.T) {
	line := `203.0.113.7 - - [12/Mar/2024:15:04:05 -0700] "GET /` + strings.Repeat("x", 1100) + ` HTTP/1.1" 200 5 "-" "UA"`
	frame := append(windowFrame(1), jsonFrame(1, messageJSON(line))...)
	// Each batch costs ~1.2 KiB. With a 2 KiB reservation per batch and a
	// 4 KiB budget, two batches fit (0+2, then 1.2+2); the third (2.4+2) waits.
	ing, _ := startIngestor(t, Options{Limits: Limits{
		MaxBatchBytes:  2 << 10,
		MaxQueuedBytes: 4 << 10,
	}})
	c := dialRaw(t, ing)

	for i := 0; i < 2; i++ {
		if _, err := c.Write(frame); err != nil {
			t.Fatalf("write: %v", err)
		}
		expectACK(t, c, 1)
	}
	if _, err := c.Write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The third batch must not be acknowledged while the budget is full.
	if err := c.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var buf [6]byte
	if _, err := io.ReadFull(c, buf[:]); err == nil {
		t.Fatalf("got frame %q while the queue budget was exhausted, want no ack yet", buf)
	} else if !os.IsTimeout(err) {
		t.Fatalf("connection failed while waiting for budget: %v", err)
	}
	if got := ing.Stats().QueueDepth; got != 2 {
		t.Fatalf("QueueDepth = %d, want 2", got)
	}

	// Draining frees the budget; the held-back batch is then read, queued
	// and acked. (It may land in the same ReadBatch call as the first two
	// or in a later one, so only the total is asserted.)
	if got := readAll(t, ing, 3); len(got) != 3 {
		t.Fatalf("got %d requests after draining, want 3", len(got))
	}
	expectACK(t, c, 1)
	if got := ing.budget.inUse(); got != 0 {
		t.Errorf("queue budget in use = %d after draining everything, want 0", got)
	}
}

func TestByteBudget(t *testing.T) {
	b := newByteBudget(10)
	if ok, _ := b.tryAcquire(6); !ok {
		t.Fatal("first acquire of 6/10 refused")
	}
	ok, wake := b.tryAcquire(5)
	if ok {
		t.Fatal("acquire of 5 with 6/10 in use succeeded")
	}
	select {
	case <-wake:
		t.Fatal("wake channel closed before any release")
	default:
	}
	b.release(2)
	select {
	case <-wake:
	default:
		t.Fatal("wake channel not closed by release")
	}
	if ok, _ := b.tryAcquire(5); !ok {
		t.Fatal("acquire of 5 with 4/10 in use refused")
	}
	if got := b.inUse(); got != 9 {
		t.Fatalf("inUse = %d, want 9", got)
	}
	b.release(9)
	// Nothing held: even a request larger than the budget is admitted, so a
	// single oversized batch can never wait forever.
	if ok, _ := b.tryAcquire(100); !ok {
		t.Fatal("oversized acquire refused on an empty budget")
	}
}

func TestLimitsNormalized(t *testing.T) {
	if got := (Limits{}).normalized(); got != DefaultLimits() {
		t.Errorf("zero Limits normalized to %+v, want defaults %+v", got, DefaultLimits())
	}
	got := Limits{MaxBatchBytes: 100, MaxQueuedBytes: 10, MaxConnections: -1}.normalized()
	if got.MaxQueuedBytes != 100 {
		t.Errorf("MaxQueuedBytes = %d, want raised to MaxBatchBytes 100", got.MaxQueuedBytes)
	}
	if got.MaxConnections != DefaultLimits().MaxConnections {
		t.Errorf("MaxConnections = %d, want default", got.MaxConnections)
	}
}

// --- fuzz -------------------------------------------------------------------

// FuzzLJReader feeds arbitrary bytes to the frame reader under tight limits.
// Whatever the input, it must not panic and must never hold more than the
// batch allowance.
func FuzzLJReader(f *testing.F) {
	valid := append(windowFrame(2), jsonFrame(1, messageJSON(testLine))...)
	valid = append(valid, compressedFrame(f, jsonFrame(2, messageJSON(testLine)))...)
	f.Add(valid)
	f.Add([]byte("2W\xff\xff\xff\xff"))
	f.Add(append(windowFrame(1), jsonFrameHeader(1, 0xffffffff)...))
	f.Add(append(windowFrame(1), '2', 'C', 0xff, 0xff, 0xff, 0xff))
	f.Add(append(windowFrame(3), compressedFrame(f, bytes.Repeat(jsonFrame(1, `{"message":"x"}`), 3))...))
	f.Add([]byte{})

	limits := Limits{MaxWindowEvents: 64, MaxEventBytes: 1 << 10, MaxBatchBytes: 8 << 10}.normalized()
	f.Fuzz(func(t *testing.T, data []byte) {
		r := newLJReader(bytes.NewReader(data), limits)
		for {
			count, err := r.readWindow()
			if err != nil {
				return
			}
			if int(count) > limits.MaxWindowEvents {
				t.Fatalf("readWindow accepted %d events, limit %d", count, limits.MaxWindowEvents)
			}
			if count == 0 {
				continue
			}
			b, err := r.readBatch(count)
			if err != nil {
				return
			}
			if len(b.msgs)+b.dropped != int(count) {
				t.Fatalf("batch holds %d+%d events, window announced %d", len(b.msgs), b.dropped, count)
			}
			var total int64
			for _, m := range b.msgs {
				total += int64(len(m))
			}
			if total > limits.MaxBatchBytes {
				t.Fatalf("batch holds %d message bytes, limit %d", total, limits.MaxBatchBytes)
			}
			if cap(r.buf) > limits.MaxEventBytes {
				t.Fatalf("scratch buffer grew to %d, limit %d", cap(r.buf), limits.MaxEventBytes)
			}
		}
	})
}
