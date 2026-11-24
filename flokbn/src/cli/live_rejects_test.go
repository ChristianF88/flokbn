package cli

import (
	"fmt"
	"testing"
	"time"

	v2 "github.com/elastic/go-lumber/client/v2"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/logparser"
)

func TestRejectWatch(t *testing.T) {
	t0 := time.Now()
	type step struct {
		parsedTotal, rejectedTotal uint64
		at                         time.Duration
		wantParsed, wantRejected   uint64
		wantWarn                   bool
	}
	for _, tc := range []struct {
		name  string
		steps []step
	}{
		{"mostly rejected batch warns", []step{
			{parsedTotal: 5, rejectedTotal: 95, wantParsed: 5, wantRejected: 95, wantWarn: true},
		}},
		{"mostly parsed batch does not warn", []step{
			{parsedTotal: 95, rejectedTotal: 5},
		}},
		{"exactly half does not warn", []step{
			{parsedTotal: 50, rejectedTotal: 50},
		}},
		{"too few lines are carried over until there are enough", []step{
			{parsedTotal: 0, rejectedTotal: 7},
			{parsedTotal: 1, rejectedTotal: 12},
			{parsedTotal: 1, rejectedTotal: 19, wantParsed: 1, wantRejected: 19, wantWarn: true},
		}},
		{"a stray rejected line among good ones never warns", []step{
			{parsedTotal: 0, rejectedTotal: 1},
			{parsedTotal: 30, rejectedTotal: 1},
			{parsedTotal: 30, rejectedTotal: 2},
			{parsedTotal: 60, rejectedTotal: 2},
		}},
		{"at most one warning per minute", []step{
			{parsedTotal: 0, rejectedTotal: 100, wantRejected: 100, wantWarn: true},
			{parsedTotal: 0, rejectedTotal: 200, at: 30 * time.Second},
			{parsedTotal: 0, rejectedTotal: 300, at: 59 * time.Second},
			// Counts only the lines since the last judgement, not the
			// minute that was rate-limited.
			{parsedTotal: 10, rejectedTotal: 400, at: 60 * time.Second, wantParsed: 10, wantRejected: 100, wantWarn: true},
		}},
		{"recovers: a good stretch after a bad one is judged on its own", []step{
			{parsedTotal: 0, rejectedTotal: 100, wantRejected: 100, wantWarn: true},
			{parsedTotal: 100, rejectedTotal: 100, at: 2 * time.Minute},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var w rejectWatch
			for i, s := range tc.steps {
				parsed, rejected, warn := w.observe(s.parsedTotal, s.rejectedTotal, t0.Add(s.at))
				if warn != s.wantWarn || parsed != s.wantParsed || rejected != s.wantRejected {
					t.Errorf("step %d: observe(%d, %d) = parsed %d, rejected %d, warn %v; want %d, %d, %v",
						i, s.parsedTotal, s.rejectedTotal, parsed, rejected, warn, s.wantParsed, s.wantRejected, s.wantWarn)
				}
			}
		})
	}
}

// countingIngestor is a fakeIngestor whose Stats reports parse totals: every
// ReadBatch adds one scripted (parsed, rejected) pair, as the real ingestor
// does while it parses the batches it drains.
type countingIngestor struct {
	*fakeIngestor
	reads            [][2]uint64
	parsed, rejected uint64
}

func (c *countingIngestor) ReadBatch() ([]accesslog.Request, error) {
	batch, err := c.fakeIngestor.ReadBatch()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.reads) > 0 {
		c.parsed += c.reads[0][0]
		c.rejected += c.reads[0][1]
		c.reads = c.reads[1:]
	}
	return batch, err
}

func (c *countingIngestor) Stats() ingestor.IngestStats {
	st := c.fakeIngestor.Stats()
	c.mu.Lock()
	defer c.mu.Unlock()
	st.RequestsTotal, st.ParseErrorsTotal = c.parsed, c.rejected
	return st
}

func rejectedLinesWarnings(events []logEvent) []logEvent {
	var out []logEvent
	for _, ev := range events {
		if ev.rec.Message == liveRejectedLinesMsg {
			out = append(out, ev)
		}
	}
	return out
}

// TestRunLiveLoop_WarnsWhenMostLinesAreRejected: a logFormat that does not
// match the shipped lines used to show only as a rising parse-error counter.
// The loop must say so, name the format in effect, and not repeat itself on
// every batch.
func TestRunLiveLoop_WarnsWhenMostLinesAreRejected(t *testing.T) {
	now := time.Now()
	const format = `%^ %^ %^ [%t] "%r" %s %b "%^" "%u" "%h"`
	ing := &countingIngestor{
		fakeIngestor: &fakeIngestor{
			batches: [][]accesslog.Request{
				noiseRequests(now, "/a")[:5],
				noiseRequests(now, "/b")[:5],
			},
			closeAfterDrain: true,
		},
		reads: [][2]uint64{{5, 95}, {5, 95}},
	}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})
	cfg.Live.LogFormat = format

	h := startLoop(t, ing, cfg)
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
	events := h.drainEvents()
	if n := len(iterationEvents(events)); n != 2 {
		t.Fatalf("iterations = %d, want 2", n)
	}
	warnings := rejectedLinesWarnings(events)
	if len(warnings) != 1 {
		t.Fatalf("%q logged %d times for two bad batches, want once (rate limit)", liveRejectedLinesMsg, len(warnings))
	}
	attrs := recordAttrs(warnings[0].rec)
	if got := attrs["log_format"].String(); got != format {
		t.Errorf("log_format = %q, want the configured format %q", got, format)
	}
	if got := fmt.Sprint(attrs["rejected"].Any(), "/", attrs["parsed"].Any(), "/", attrs["parse_errors_total"].Any()); got != "95/5/95" {
		t.Errorf("rejected/parsed/parse_errors_total = %s, want 95/5/95", got)
	}
	if _, ok := attrs["hint"]; !ok {
		t.Errorf("warning carries no hint (attrs: %v)", attrs)
	}
}

// TestRunLiveLoop_WarnsWhenEveryLineIsRejected: with a format that matches
// nothing, ReadBatch returns no requests at all and the loop takes the idle
// path. The warning must come from there too.
func TestRunLiveLoop_WarnsWhenEveryLineIsRejected(t *testing.T) {
	ing := &countingIngestor{
		fakeIngestor: &fakeIngestor{}, // no requests ever, stays open
		reads:        [][2]uint64{{0, 40}},
	}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})

	h := startLoop(t, ing, cfg)
	h.awaitMessage(liveRejectedLinesMsg)
	// The format in effect is the live default when none is configured.
	_, snap := h.nextHeartbeat()
	if snap.Loop.Iterations != 0 {
		t.Errorf("loop.iterations = %d, want 0 (nothing parsed)", snap.Loop.Iterations)
	}
}

// TestRunLiveLoop_NoRejectWarningForGoodTraffic: the occasional bad line must
// not trigger the warning.
func TestRunLiveLoop_NoRejectWarningForGoodTraffic(t *testing.T) {
	now := time.Now()
	ing := &countingIngestor{
		fakeIngestor: &fakeIngestor{
			batches:         [][]accesslog.Request{hotBlock(10, 5, 5, now, "/"), hotBlock(10, 5, 5, now, "/")},
			closeAfterDrain: true,
		},
		reads: [][2]uint64{{256, 3}, {256, 0}},
	}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})

	h := startLoop(t, ing, cfg)
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
	if warnings := rejectedLinesWarnings(h.drainEvents()); len(warnings) != 0 {
		t.Errorf("%q logged %d times for traffic that parses, want none", liveRejectedLinesMsg, len(warnings))
	}
}

// TestLiveLoop_EndToEnd_MismatchedFormatWarns ships real lines that do not
// fit the format in effect through the real ingestor: IP-last lines against
// the IP-first live default.
func TestLiveLoop_EndToEnd_MismatchedFormatWarns(t *testing.T) {
	ing := newE2EIngestor(t)
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})

	h := startLoop(t, ing, cfg)
	h.awaitMessage(liveAcceptingMsg)

	ts := time.Now().Format("02/Jan/2006:15:04:05 -0700")
	events := make([]interface{}, 0, 60)
	for i := 0; i < 60; i++ {
		line := fmt.Sprintf(`proxy.example - - [%s] "GET / HTTP/1.1" 200 123 "-" "TestUA" "10.5.5.%d"`, ts, i)
		events = append(events, map[string]interface{}{"message": line})
	}
	client, err := v2.SyncDial(ing.Addr().String())
	if err != nil {
		t.Fatalf("SyncDial: %v", err)
	}
	defer client.Close()
	if _, err := client.Send(events); err != nil {
		t.Fatalf("Send: %v", err)
	}

	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev := <-h.events:
			if ev.rec.Message != liveRejectedLinesMsg {
				continue
			}
			attrs := recordAttrs(ev.rec)
			if got := attrs["log_format"].String(); got != logparser.DefaultLiveLogFormat {
				t.Errorf("log_format = %q, want the live default %q", got, logparser.DefaultLiveLogFormat)
			}
			if got := attrs["rejected"].Uint64(); got != 60 {
				t.Errorf("rejected = %d, want 60", got)
			}
			return
		case <-deadline:
			t.Fatalf("no %q warning for 60 lines that do not match the format", liveRejectedLinesMsg)
		}
	}
}
