package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/jail"
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

type loopHarness struct {
	t       *testing.T
	outputs chan *output.JSONOutput
	done    chan struct{}
	err     error
	cancel  context.CancelFunc
}

// startLoop runs runLiveLoop in a goroutine. Emissions go to a buffered
// channel; t.Cleanup cancels the loop and requires it to exit within 5s.
func startLoop(t *testing.T, ing ingestor.Ingestor, cfg *config.Config) *loopHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h := &loopHarness{
		t:       t,
		outputs: make(chan *output.JSONOutput, 64),
		done:    make(chan struct{}),
		cancel:  cancel,
	}
	go func() {
		h.err = runLiveLoop(ctx, ing, cfg, func(o *output.JSONOutput) { h.outputs <- o }, nil)
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

// nextStats returns the next emitted LiveStats, skipping info-only outputs.
func (h *loopHarness) nextStats() *output.LiveStats {
	h.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case o := <-h.outputs:
			if o.LiveStats != nil {
				return o.LiveStats
			}
		case <-deadline:
			h.t.Fatal("timed out waiting for LiveStats output")
			return nil
		}
	}
}

// awaitMessage consumes outputs until one carries the given warning message.
func (h *loopHarness) awaitMessage(msg string) {
	h.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case o := <-h.outputs:
			for _, w := range o.Warnings {
				if w.Message == msg {
					return
				}
			}
		case <-deadline:
			h.t.Fatalf("timed out waiting for output message %q", msg)
		}
	}
}

// drainOutputs non-blockingly empties the output channel.
func (h *loopHarness) drainOutputs() []*output.JSONOutput {
	var all []*output.JSONOutput
	for {
		select {
		case o := <-h.outputs:
			all = append(all, o)
		default:
			return all
		}
	}
}

func outputsHaveMessage(outs []*output.JSONOutput, msg string) bool {
	for _, o := range outs {
		for _, w := range o.Warnings {
			if w.Message == msg {
				return true
			}
		}
	}
	return false
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

func assertSingleCIDRStats(t *testing.T, stats *output.LiveStats, wantCIDR string, wantCount uint32) {
	t.Helper()
	if len(stats.DetectedCIDRs) != 1 || stats.DetectedCIDRs[0].CIDR != wantCIDR || stats.DetectedCIDRs[0].Count != wantCount {
		t.Errorf("DetectedCIDRs = %+v, want [{%s %d}]", stats.DetectedCIDRs, wantCIDR, wantCount)
	}
	if len(stats.MergedCIDRs) != 1 || stats.MergedCIDRs[0] != wantCIDR {
		t.Errorf("MergedCIDRs = %v, want [%s]", stats.MergedCIDRs, wantCIDR)
	}
	if len(stats.ActiveBans) != 1 || stats.ActiveBans[0] != wantCIDR {
		t.Errorf("ActiveBans = %v, want [%s]", stats.ActiveBans, wantCIDR)
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

	stats := h.nextStats()
	if stats.ProcessedBatch != 276 {
		t.Errorf("ProcessedBatch = %d, want 276", stats.ProcessedBatch)
	}
	if stats.WindowSize != 276 {
		t.Errorf("WindowSize = %d, want 276", stats.WindowSize)
	}
	assertSingleCIDRStats(t, stats, "10.5.5.0/24", 256)

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

	stats := h.nextStats()
	if stats.ProcessedBatch != 512 {
		t.Errorf("ProcessedBatch = %d, want 512", stats.ProcessedBatch)
	}
	if stats.WindowSize != 256 {
		t.Errorf("WindowSize = %d, want 256 (only /api requests pass the filter)", stats.WindowSize)
	}
	assertSingleCIDRStats(t, stats, "10.5.5.0/24", 256)
	for _, d := range stats.DetectedCIDRs {
		if d.CIDR == "10.6.6.0/24" {
			t.Errorf("filtered range 10.6.6.0/24 must not be detected, got %+v", stats.DetectedCIDRs)
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

	stats := h.nextStats()
	if stats.ProcessedBatch != 512 {
		t.Errorf("ProcessedBatch = %d, want 512", stats.ProcessedBatch)
	}
	// "all" holds 512 requests, "api" holds 256 -> reported sum is 768.
	if stats.WindowSize != 768 {
		t.Errorf("WindowSize = %d, want 768", stats.WindowSize)
	}

	// Window iteration order is map order, so compare as multiset:
	// "all" detects both /24s, "api" detects only 10.5.5.0/24.
	detected := map[string]int{}
	for _, d := range stats.DetectedCIDRs {
		detected[d.CIDR]++
	}
	if detected["10.5.5.0/24"] != 2 || detected["10.6.6.0/24"] != 1 || len(detected) != 2 {
		t.Errorf("DetectedCIDRs multiset = %v, want {10.5.5.0/24:2 10.6.6.0/24:1}", detected)
	}

	merged := map[string]bool{}
	for _, c := range stats.MergedCIDRs {
		merged[c] = true
	}
	if len(stats.MergedCIDRs) != 2 || !merged["10.5.5.0/24"] || !merged["10.6.6.0/24"] {
		t.Errorf("MergedCIDRs = %v, want both /24s exactly once", stats.MergedCIDRs)
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

	stats := h.nextStats()
	if len(stats.DetectedCIDRs) != 1 || stats.DetectedCIDRs[0].CIDR != "10.5.5.0/24" {
		t.Errorf("DetectedCIDRs = %+v, want [{10.5.5.0/24 256}]", stats.DetectedCIDRs)
	}
	if len(stats.MergedCIDRs) != 0 {
		t.Errorf("MergedCIDRs = %v, want empty (useForJail=false)", stats.MergedCIDRs)
	}
	if len(stats.ActiveBans) != 0 {
		t.Errorf("ActiveBans = %v, want empty", stats.ActiveBans)
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

	stats := h.nextStats()
	if stats.ProcessedBatch != 276 {
		t.Errorf("ProcessedBatch = %d, want 276", stats.ProcessedBatch)
	}
	if stats.WindowSize != 20 {
		t.Errorf("WindowSize = %d, want 20 (stale hot range evicted)", stats.WindowSize)
	}
	if len(stats.DetectedCIDRs) != 0 {
		t.Errorf("DetectedCIDRs = %+v, want empty (hot range evicted before clustering)", stats.DetectedCIDRs)
	}
	if len(stats.ActiveBans) != 0 {
		t.Errorf("ActiveBans = %v, want empty", stats.ActiveBans)
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

	stats1 := h.nextStats()
	if stats1.WindowSize != 256 {
		t.Errorf("iter1 WindowSize = %d, want 256", stats1.WindowSize)
	}
	assertSingleCIDRStats(t, stats1, "10.5.5.0/24", 256)

	stats2 := h.nextStats()
	if stats2.ProcessedBatch != 20 {
		t.Errorf("iter2 ProcessedBatch = %d, want 20", stats2.ProcessedBatch)
	}
	if stats2.WindowSize != 256 {
		t.Errorf("iter2 WindowSize = %d, want 256 (maxSize eviction trimmed 20 oldest)", stats2.WindowSize)
	}
	// 20 hot IPs were evicted, the surviving 236 still cluster to the /24.
	if len(stats2.DetectedCIDRs) != 1 || stats2.DetectedCIDRs[0].CIDR != "10.5.5.0/24" || stats2.DetectedCIDRs[0].Count != 236 {
		t.Errorf("iter2 DetectedCIDRs = %+v, want [{10.5.5.0/24 236}]", stats2.DetectedCIDRs)
	}
	if len(stats2.ActiveBans) != 1 || stats2.ActiveBans[0] != "10.5.5.0/24" {
		t.Errorf("iter2 ActiveBans = %v, want [10.5.5.0/24] (ban persists)", stats2.ActiveBans)
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

	stats := h.nextStats()
	if len(stats.ActiveBans) != 1 || stats.ActiveBans[0] != "10.5.5.0/24" {
		t.Errorf("ActiveBans = %v, want [10.5.5.0/24]", stats.ActiveBans)
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
	if outs := h.drainOutputs(); !outputsHaveMessage(outs, "Ingestor closed. Exiting loop.") {
		t.Errorf("missing %q output after cancel", "Ingestor closed. Exiting loop.")
	}
}

func TestRunLiveLoop_NoLiveTriesErrors(t *testing.T) {
	fake := &fakeIngestor{}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{})

	err := runLiveLoop(context.Background(), fake, cfg, func(*output.JSONOutput) {}, nil)
	if err == nil || !strings.Contains(err.Error(), "no LiveTries configurations found") {
		t.Fatalf("err = %v, want 'no LiveTries configurations found'", err)
	}
	if got := fake.acceptCallCount(); got != 0 {
		t.Errorf("Accept calls = %d, want 0", got)
	}
}
