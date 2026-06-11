package cli

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/jail"
	"github.com/ChristianF88/cidrx/logging"
	"github.com/ChristianF88/cidrx/output"
)

// ============================================================================
// Fake ingestor
// ============================================================================

// fakeIngestor scripts a fixed sequence of batches for runLiveLoop. All state
// is mutex-guarded because Close is called from the loop's cancellation
// watcher goroutine.
type fakeIngestor struct {
	mu              sync.Mutex
	batches         [][]ingestor.Request
	closed          bool
	closeCalls      int
	acceptCalls     int
	closeAfterDrain bool
}

var _ ingestor.Ingestor = (*fakeIngestor)(nil)

func (f *fakeIngestor) Accept() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acceptCalls++
	return nil
}

func (f *fakeIngestor) ReadBatch() ([]ingestor.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.batches) == 0 {
		if f.closeAfterDrain {
			f.closed = true
		}
		return nil, nil
	}
	batch := f.batches[0]
	f.batches = f.batches[1:]
	return batch, nil
}

func (f *fakeIngestor) IsClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *fakeIngestor) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCalls++
	f.closed = true
	return nil
}

func (f *fakeIngestor) Stats() ingestor.IngestStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	return ingestor.IngestStats{QueueDepth: len(f.batches)}
}

func (f *fakeIngestor) closeCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closeCalls
}

func (f *fakeIngestor) acceptCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.acceptCalls
}

// ============================================================================
// Test corpus
//
// Hot range: one request per IP in <o1>.<o2>.<o3>.0/24 (256 requests). With
// ClusterArgSet {100, 24, 32, 0.5} the /24 node has both /25 children at
// exactly 128 each (equal-count fast path), Count 256 >= 100 and depth
// 24 >= minDepth, so clustering emits exactly that /24 and stops descending.
// Noise: 20 singleton IPs across distinct /8s, pruned by Count < 100.
// ============================================================================

func mkRequest(o1, o2, o3, o4 byte, ts time.Time, uri string) ingestor.Request {
	return ingestor.Request{
		IPUint32:  uint32(o1)<<24 | uint32(o2)<<16 | uint32(o3)<<8 | uint32(o4),
		Status:    200,
		Method:    ingestor.GET,
		Timestamp: ts,
		URI:       uri,
		UserAgent: "TestUA",
	}
}

// hotBlock returns one request per IP in o1.o2.o3.0/24 (256 requests).
func hotBlock(o1, o2, o3 byte, ts time.Time, uri string) []ingestor.Request {
	reqs := make([]ingestor.Request, 0, 256)
	for i := 0; i < 256; i++ {
		reqs = append(reqs, mkRequest(o1, o2, o3, byte(i), ts, uri))
	}
	return reqs
}

// noiseRequests returns 20 singleton IPs spread across distinct /8s.
func noiseRequests(ts time.Time, uri string) []ingestor.Request {
	reqs := make([]ingestor.Request, 0, 20)
	for i := 0; i < 20; i++ {
		reqs = append(reqs, mkRequest(byte(20+i), byte(i+1), byte(i+2), byte(i+3), ts, uri))
	}
	return reqs
}

func testClusterArgSet() config.ClusterArgSet {
	return config.ClusterArgSet{
		MinClusterSize:       100,
		MinDepth:             24,
		MaxDepth:             32,
		MeanSubnetDifference: 0.5,
	}
}

func newWindowConfigSized(t *testing.T, endpointRegex string, useForJail bool, maxTime time.Duration, maxSize int) *config.SlidingTrieConfig {
	t.Helper()
	stc := &config.SlidingTrieConfig{
		EndpointRegex:          endpointRegex,
		SlidingWindowMaxTime:   maxTime,
		SlidingWindowMaxSize:   maxSize,
		SleepBetweenIterations: 0, // keep the loop fast in tests
		ClusterArgSets:         []config.ClusterArgSet{testClusterArgSet()},
		UseForJail:             []bool{useForJail},
	}
	if err := stc.CompileRegex(); err != nil {
		t.Fatalf("CompileRegex: %v", err)
	}
	return stc
}

func newWindowConfig(t *testing.T, endpointRegex string, useForJail bool) *config.SlidingTrieConfig {
	return newWindowConfigSized(t, endpointRegex, useForJail, 24*time.Hour, 100000)
}

func newLiveConfig(t *testing.T, windows map[string]*config.SlidingTrieConfig) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		Global: &config.GlobalConfig{
			JailFile: filepath.Join(dir, "jail.json"),
			BanFile:  filepath.Join(dir, "ban.txt"),
		},
		Live:      &config.LiveConfig{Port: "0"},
		LiveTries: windows,
	}
}

// ============================================================================
// Harness
// ============================================================================

// logEvent is one captured slog record. For "iteration" records snap holds
// the snapshot published just before the log call (the loop publishes before
// logging, and the handler runs synchronously on the loop goroutine, so this
// pairing is race-free and exact).
type logEvent struct {
	rec  slog.Record
	snap *statsSnapshot
}

// chanHandler is a slog.Handler streaming every record to a channel.
type chanHandler struct {
	ch    chan logEvent
	srv   *statsServer
	attrs []slog.Attr
}

func (h *chanHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *chanHandler) Handle(_ context.Context, r slog.Record) error {
	rec := r.Clone()
	rec.AddAttrs(h.attrs...)
	ev := logEvent{rec: rec}
	if r.Message == "iteration" {
		ev.snap = h.srv.snap.Load()
	}
	h.ch <- ev
	return nil
}

func (h *chanHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &chanHandler{ch: h.ch, srv: h.srv, attrs: merged}
}

func (h *chanHandler) WithGroup(string) slog.Handler { return h }

// discardLogger returns a debug-level logger for runLiveLoop calls whose log
// output is irrelevant to the test.
func discardLogger(t *testing.T) *slog.Logger {
	t.Helper()
	logger, err := logging.New(io.Discard, "debug", "text")
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	return logger
}

// iterStats is the parsed attribute set of one "iteration" log record.
type iterStats struct {
	Window         int
	Batch          int
	Detected       int
	Merged         int
	Jailed         int
	ActiveBans     int
	BanFileWritten bool
	LoopMS         int64
	ClusterMS      int64
}

func recordAttrs(r slog.Record) map[string]slog.Value {
	m := map[string]slog.Value{}
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value
		return true
	})
	return m
}

func parseIteration(t *testing.T, r slog.Record) iterStats {
	t.Helper()
	m := recordAttrs(r)
	getInt := func(key string) int64 {
		v, ok := m[key]
		if !ok {
			t.Fatalf("iteration record missing attr %q (attrs: %v)", key, m)
		}
		return v.Int64()
	}
	written, ok := m["ban_file_written"]
	if !ok {
		t.Fatalf("iteration record missing attr ban_file_written (attrs: %v)", m)
	}
	return iterStats{
		Window:         int(getInt("window")),
		Batch:          int(getInt("batch")),
		Detected:       int(getInt("detected")),
		Merged:         int(getInt("merged")),
		Jailed:         int(getInt("jailed")),
		ActiveBans:     int(getInt("active_bans")),
		BanFileWritten: written.Bool(),
		LoopMS:         getInt("loop_ms"),
		ClusterMS:      getInt("cluster_ms"),
	}
}

type loopHarness struct {
	t      *testing.T
	events chan logEvent
	done   chan struct{}
	err    error
	cancel context.CancelFunc
	srv    *statsServer
}

// startLoopWith runs runLiveLoop in a goroutine with a record-capturing
// logger and the given stats server (every test gets snapshots: a bare
// statsServer works because publish only touches the atomic pointer).
// t.Cleanup cancels the loop and requires it to exit within 5s.
func startLoopWith(t *testing.T, ing ingestor.Ingestor, cfg *config.Config, srv *statsServer) *loopHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h := &loopHarness{
		t:      t,
		events: make(chan logEvent, 256),
		done:   make(chan struct{}),
		cancel: cancel,
		srv:    srv,
	}
	logger := slog.New(&chanHandler{ch: h.events, srv: srv})
	go func() {
		h.err = runLiveLoop(ctx, ing, cfg, logger, srv)
		close(h.done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
			t.Error("runLiveLoop did not exit within 5s after cancel")
		}
	})
	return h
}

// startLoop runs the loop with a publish-only stats server.
func startLoop(t *testing.T, ing ingestor.Ingestor, cfg *config.Config) *loopHarness {
	t.Helper()
	return startLoopWith(t, ing, cfg, &statsServer{})
}

// wait blocks until runLiveLoop returns and yields its error. The timeout is
// a failure bound, not a synchronization sleep.
func (h *loopHarness) wait(timeout time.Duration) error {
	h.t.Helper()
	select {
	case <-h.done:
		return h.err
	case <-time.After(timeout):
		h.t.Fatalf("runLiveLoop did not finish within %v", timeout)
		return nil
	}
}

// nextIteration returns the next "iteration" log record (parsed) together
// with the snapshot published for exactly that iteration.
func (h *loopHarness) nextIteration() (iterStats, *statsSnapshot) {
	h.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev := <-h.events:
			if ev.rec.Message == "iteration" {
				return parseIteration(h.t, ev.rec), ev.snap
			}
		case <-deadline:
			h.t.Fatal("timed out waiting for iteration log record")
			return iterStats{}, nil
		}
	}
}

// awaitMessage consumes events until one carries the given log message.
func (h *loopHarness) awaitMessage(msg string) {
	h.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev := <-h.events:
			if ev.rec.Message == msg {
				return
			}
		case <-deadline:
			h.t.Fatalf("timed out waiting for log message %q", msg)
		}
	}
}

// drainEvents non-blockingly empties the event channel.
func (h *loopHarness) drainEvents() []logEvent {
	var all []logEvent
	for {
		select {
		case ev := <-h.events:
			all = append(all, ev)
		default:
			return all
		}
	}
}

func eventsHaveMessage(events []logEvent, msg string) bool {
	for _, ev := range events {
		if ev.rec.Message == msg {
			return true
		}
	}
	return false
}

func countMessages(events []logEvent, msg string) int {
	n := 0
	for _, ev := range events {
		if ev.rec.Message == msg {
			n++
		}
	}
	return n
}

// iterationEvents extracts every "iteration" event from a drained slice.
func iterationEvents(events []logEvent) []logEvent {
	var iters []logEvent
	for _, ev := range events {
		if ev.rec.Message == "iteration" {
			iters = append(iters, ev)
		}
	}
	return iters
}

// detectedNow flattens all cluster-set detections in a snapshot, preserving
// window/set order.
func detectedNow(snap *statsSnapshot) []output.LiveCIDR {
	var all []output.LiveCIDR
	for _, w := range snap.Windows {
		for _, cs := range w.ClusterSets {
			all = append(all, cs.DetectedNow...)
		}
	}
	return all
}

// jailActiveCIDRs lists the CIDRs of the snapshot's active bans (jail truth;
// equals the ban-file view when no whitelist is configured).
func jailActiveCIDRs(snap *statsSnapshot) []string {
	var cidrs []string
	for _, b := range snap.Jail.ActiveBans {
		cidrs = append(cidrs, b.CIDR)
	}
	return cidrs
}

// banCIDRs returns the non-comment, non-empty lines of the ban file. A
// missing file yields nil (the loop may not have written it yet only if no
// iteration ran, which the callers rule out).
func banCIDRs(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading ban file %s: %v", path, err)
	}
	var cidrs []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cidrs = append(cidrs, line)
	}
	return cidrs
}

// findPrisoner loads the jail file and locates a CIDR's prisoner entry.
func findPrisoner(t *testing.T, jailFile, cidr string) (cellID int, active bool, found bool) {
	t.Helper()
	j, err := jail.FileToJail(jailFile)
	if err != nil {
		t.Fatalf("reading jail file %s: %v", jailFile, err)
	}
	for _, cell := range j.Cells {
		for _, p := range cell.Prisoners {
			if p.CIDR == cidr {
				return cell.ID, p.BanActive, true
			}
		}
	}
	return 0, false, false
}

// assertSingleCIDRState checks that exactly one CIDR was detected, merged and
// actively banned in the given iteration: counts come from the iteration log
// record, identities from the paired snapshot (jail truth equals the filtered
// ban view because these tests configure no whitelist).
func assertSingleCIDRState(t *testing.T, it iterStats, snap *statsSnapshot, wantCIDR string, wantCount uint32) {
	t.Helper()
	detected := detectedNow(snap)
	if len(detected) != 1 || detected[0].CIDR != wantCIDR || detected[0].Count != wantCount {
		t.Errorf("detected CIDRs = %+v, want [{%s %d}]", detected, wantCIDR, wantCount)
	}
	if it.Detected != 1 || it.Merged != 1 {
		t.Errorf("iteration detected/merged = %d/%d, want 1/1", it.Detected, it.Merged)
	}
	if bans := jailActiveCIDRs(snap); len(bans) != 1 || bans[0] != wantCIDR {
		t.Errorf("active bans = %v, want [%s]", bans, wantCIDR)
	}
	if it.ActiveBans != 1 {
		t.Errorf("iteration active_bans = %d, want 1", it.ActiveBans)
	}
}

// ============================================================================
// Tests
// ============================================================================

func TestRunLiveLoop_SingleIterationBansCluster(t *testing.T) {
	now := time.Now()
	batch := append(hotBlock(10, 5, 5, now, "/api/item"), noiseRequests(now, "/api/item")...)
	fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})

	h := startLoop(t, fake, cfg)

	it, snap := h.nextIteration()
	if it.Batch != 276 {
		t.Errorf("iteration batch = %d, want 276", it.Batch)
	}
	if it.Window != 276 {
		t.Errorf("iteration window = %d, want 276", it.Window)
	}
	assertSingleCIDRState(t, it, snap, "10.5.5.0/24", 256)

	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}

	bans := banCIDRs(t, cfg.GetBanFile())
	if len(bans) != 1 || bans[0] != "10.5.5.0/24" {
		t.Errorf("ban file CIDRs = %v, want [10.5.5.0/24]", bans)
	}
	cellID, active, found := findPrisoner(t, cfg.GetJailFile(), "10.5.5.0/24")
	if !found {
		t.Fatal("10.5.5.0/24 not found in jail file")
	}
	if cellID != 1 || !active {
		t.Errorf("prisoner cell ID = %d active = %v, want cell 1 active", cellID, active)
	}
}

func TestRunLiveLoop_RegexFilterExcludes(t *testing.T) {
	now := time.Now()
	batch := append(hotBlock(10, 5, 5, now, "/api/item"), hotBlock(10, 6, 6, now, "/static/img")...)
	fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"api": newWindowConfig(t, "^/api", true),
	})

	h := startLoop(t, fake, cfg)

	it, snap := h.nextIteration()
	if it.Batch != 512 {
		t.Errorf("iteration batch = %d, want 512", it.Batch)
	}
	if it.Window != 256 {
		t.Errorf("iteration window = %d, want 256 (only /api requests pass the filter)", it.Window)
	}
	assertSingleCIDRState(t, it, snap, "10.5.5.0/24", 256)
	for _, d := range detectedNow(snap) {
		if d.CIDR == "10.6.6.0/24" {
			t.Errorf("filtered range 10.6.6.0/24 must not be detected, got %+v", detectedNow(snap))
		}
	}

	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
}

func TestRunLiveLoop_MultiWindowMerge(t *testing.T) {
	now := time.Now()
	batch := append(hotBlock(10, 5, 5, now, "/api/item"), hotBlock(10, 6, 6, now, "/static/img")...)
	fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"all": newWindowConfig(t, "", true),
		"api": newWindowConfig(t, "^/api", true),
	})

	h := startLoop(t, fake, cfg)

	it, snap := h.nextIteration()
	if it.Batch != 512 {
		t.Errorf("iteration batch = %d, want 512", it.Batch)
	}
	// "all" holds 512 requests, "api" holds 256 -> reported sum is 768.
	if it.Window != 768 {
		t.Errorf("iteration window = %d, want 768", it.Window)
	}

	// Window iteration order is map order, so compare as multiset:
	// "all" detects both /24s, "api" detects only 10.5.5.0/24.
	detected := map[string]int{}
	for _, d := range detectedNow(snap) {
		detected[d.CIDR]++
	}
	if detected["10.5.5.0/24"] != 2 || detected["10.6.6.0/24"] != 1 || len(detected) != 2 {
		t.Errorf("detected multiset = %v, want {10.5.5.0/24:2 10.6.6.0/24:1}", detected)
	}
	if it.Detected != 3 {
		t.Errorf("iteration detected = %d, want 3", it.Detected)
	}

	if it.Merged != 2 {
		t.Errorf("iteration merged = %d, want 2 (both /24s exactly once)", it.Merged)
	}
	active := map[string]bool{}
	for _, c := range jailActiveCIDRs(snap) {
		active[c] = true
	}
	if len(active) != 2 || !active["10.5.5.0/24"] || !active["10.6.6.0/24"] {
		t.Errorf("active bans = %v, want both /24s", jailActiveCIDRs(snap))
	}

	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}

	bans := banCIDRs(t, cfg.GetBanFile())
	banned := map[string]bool{}
	for _, c := range bans {
		banned[c] = true
	}
	if len(bans) != 2 || !banned["10.5.5.0/24"] || !banned["10.6.6.0/24"] {
		t.Errorf("ban file CIDRs = %v, want both /24s", bans)
	}
}

func TestRunLiveLoop_UseForJailFalseDetectsButDoesNotBan(t *testing.T) {
	now := time.Now()
	batch := append(hotBlock(10, 5, 5, now, "/api/item"), noiseRequests(now, "/api/item")...)
	fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", false),
	})

	h := startLoop(t, fake, cfg)

	it, snap := h.nextIteration()
	detected := detectedNow(snap)
	if len(detected) != 1 || detected[0].CIDR != "10.5.5.0/24" {
		t.Errorf("detected CIDRs = %+v, want [{10.5.5.0/24 256}]", detected)
	}
	if it.Merged != 0 {
		t.Errorf("iteration merged = %d, want 0 (useForJail=false)", it.Merged)
	}
	if it.ActiveBans != 0 || len(jailActiveCIDRs(snap)) != 0 {
		t.Errorf("active bans = %v (count %d), want empty", jailActiveCIDRs(snap), it.ActiveBans)
	}

	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}

	if bans := banCIDRs(t, cfg.GetBanFile()); len(bans) != 0 {
		t.Errorf("ban file CIDRs = %v, want none", bans)
	}
	if _, _, found := findPrisoner(t, cfg.GetJailFile(), "10.5.5.0/24"); found {
		t.Error("10.5.5.0/24 must not be in jail when useForJail=false")
	}
}

// TestRunLiveLoop_WindowEvictionByTime: DropOld's cutoff is wall-clock based,
// so cross-iteration time eviction cannot be made deterministic without
// sleeping. Instead a single batch mixes 256 hot requests that are already
// older than the 1h window with 20 fresh noise requests: the hot range is
// evicted before clustering runs.
func TestRunLiveLoop_WindowEvictionByTime(t *testing.T) {
	now := time.Now()
	batch := append(hotBlock(10, 5, 5, now.Add(-2*time.Hour), "/api/item"), noiseRequests(now, "/api/item")...)
	fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfigSized(t, "", true, time.Hour, 100000),
	})

	h := startLoop(t, fake, cfg)

	it, snap := h.nextIteration()
	if it.Batch != 276 {
		t.Errorf("iteration batch = %d, want 276", it.Batch)
	}
	if it.Window != 20 {
		t.Errorf("iteration window = %d, want 20 (stale hot range evicted)", it.Window)
	}
	if detected := detectedNow(snap); len(detected) != 0 {
		t.Errorf("detected CIDRs = %+v, want empty (hot range evicted before clustering)", detected)
	}
	if it.ActiveBans != 0 || len(jailActiveCIDRs(snap)) != 0 {
		t.Errorf("active bans = %v (count %d), want empty", jailActiveCIDRs(snap), it.ActiveBans)
	}

	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
}

// TestRunLiveLoop_WindowEvictionByMaxSize: iteration 1 fills the window to
// its max size and bans the hot /24; iteration 2 adds 20 noise requests,
// which evicts the 20 oldest hot entries (queue stays at maxSize) while the
// jail ban persists.
func TestRunLiveLoop_WindowEvictionByMaxSize(t *testing.T) {
	now := time.Now()
	fake := &fakeIngestor{
		batches: [][]ingestor.Request{
			hotBlock(10, 5, 5, now, "/api/item"),
			noiseRequests(now, "/api/item"),
		},
		closeAfterDrain: true,
	}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfigSized(t, "", true, 24*time.Hour, 256),
	})

	h := startLoop(t, fake, cfg)

	it1, snap1 := h.nextIteration()
	if it1.Window != 256 {
		t.Errorf("iter1 window = %d, want 256", it1.Window)
	}
	assertSingleCIDRState(t, it1, snap1, "10.5.5.0/24", 256)

	it2, snap2 := h.nextIteration()
	if it2.Batch != 20 {
		t.Errorf("iter2 batch = %d, want 20", it2.Batch)
	}
	if it2.Window != 256 {
		t.Errorf("iter2 window = %d, want 256 (maxSize eviction trimmed 20 oldest)", it2.Window)
	}
	// 20 hot IPs were evicted, the surviving 236 still cluster to the /24.
	detected2 := detectedNow(snap2)
	if len(detected2) != 1 || detected2[0].CIDR != "10.5.5.0/24" || detected2[0].Count != 236 {
		t.Errorf("iter2 detected = %+v, want [{10.5.5.0/24 236}]", detected2)
	}
	if bans := jailActiveCIDRs(snap2); len(bans) != 1 || bans[0] != "10.5.5.0/24" {
		t.Errorf("iter2 active bans = %v, want [10.5.5.0/24] (ban persists)", bans)
	}

	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
}

func TestRunLiveLoop_JailEscalation(t *testing.T) {
	now := time.Now()
	batch := append(hotBlock(10, 5, 5, now, "/api/item"), noiseRequests(now, "/api/item")...)
	fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})

	// Pre-seed the jail: 10.5.5.0/24 sits in cell 1 (10min duration) with a
	// ban that started 1h ago. UpdateBanActiveStatus will mark it inactive,
	// and re-detection must escalate it to cell 2 (4h).
	seeded := jail.NewJail()
	seeded.Cells[0].Prisoners = append(seeded.Cells[0].Prisoners, jail.Prisoner{
		CIDR:      "10.5.5.0/24",
		BanStart:  now.Add(-time.Hour),
		BanActive: true,
	})
	seeded.AllCIDRs = append(seeded.AllCIDRs, "10.5.5.0/24")
	if err := jail.JailToFile(seeded, cfg.GetJailFile()); err != nil {
		t.Fatalf("seeding jail file: %v", err)
	}

	h := startLoop(t, fake, cfg)

	_, snap := h.nextIteration()
	if bans := jailActiveCIDRs(snap); len(bans) != 1 || bans[0] != "10.5.5.0/24" {
		t.Errorf("active bans = %v, want [10.5.5.0/24]", bans)
	}

	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}

	cellID, active, found := findPrisoner(t, cfg.GetJailFile(), "10.5.5.0/24")
	if !found {
		t.Fatal("10.5.5.0/24 not found in jail file")
	}
	if cellID != 2 || !active {
		t.Errorf("prisoner cell ID = %d active = %v, want escalation to cell 2 active", cellID, active)
	}
}

func TestRunLiveLoop_ContextCancelClosesIngestorAndReturns(t *testing.T) {
	fake := &fakeIngestor{} // no batches, stays open until Close
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})

	h := startLoop(t, fake, cfg)
	h.awaitMessage("Filebeat connected")

	h.cancel()
	if err := h.wait(2 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
	if got := fake.closeCallCount(); got != 1 {
		t.Errorf("Close calls = %d, want 1", got)
	}
	if events := h.drainEvents(); !eventsHaveMessage(events, "ingestor closed, exiting loop") {
		t.Errorf("missing %q log record after cancel", "ingestor closed, exiting loop")
	}
}

func TestRunLiveLoop_NoLiveTriesErrors(t *testing.T) {
	fake := &fakeIngestor{}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{})

	err := runLiveLoop(context.Background(), fake, cfg, discardLogger(t), nil)
	if err == nil || !strings.Contains(err.Error(), "no LiveTries configurations found") {
		t.Fatalf("err = %v, want 'no LiveTries configurations found'", err)
	}
	if got := fake.acceptCallCount(); got != 0 {
		t.Errorf("Accept calls = %d, want 0", got)
	}
}
