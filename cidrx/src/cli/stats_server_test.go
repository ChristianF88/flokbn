package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/output"
)

// ============================================================================
// Harness
// ============================================================================

// newTestStatsServer binds 127.0.0.1:0, starts serving, and registers
// shutdown as cleanup (shutdown is idempotent, tests may call it earlier).
func newTestStatsServer(t *testing.T) *statsServer {
	t.Helper()
	srv, err := newStatsServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("newStatsServer: %v", err)
	}
	srv.start()
	t.Cleanup(srv.shutdown)
	return srv
}

// startLoopWithStats mirrors startLoop but threads a stats server through.
func startLoopWithStats(t *testing.T, ing ingestor.Ingestor, cfg *config.Config, srv *statsServer) *loopHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h := &loopHarness{
		t:       t,
		outputs: make(chan *output.JSONOutput, 64),
		done:    make(chan struct{}),
		cancel:  cancel,
	}
	go func() {
		h.err = runLiveLoop(ctx, ing, cfg, func(o *output.JSONOutput) { h.outputs <- o }, srv)
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

// httpGet fetches a path from the stats server and returns status, headers
// and body.
func httpGet(t *testing.T, srv *statsServer, path string) (int, http.Header, []byte) {
	t.Helper()
	resp, err := http.Get("http://" + srv.addr() + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading GET %s body: %v", path, err)
	}
	return resp.StatusCode, resp.Header, body
}

// getSnapshot GETs /stats expecting 200 and decodes the JSON into the
// snapshot struct (exported fields round-trip; tests live in package cli).
func getSnapshot(t *testing.T, srv *statsServer) *statsSnapshot {
	t.Helper()
	status, header, body := httpGet(t, srv, "/stats")
	if status != http.StatusOK {
		t.Fatalf("GET /stats status = %d, want 200 (body %q)", status, body)
	}
	if ct := header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("GET /stats Content-Type = %q, want application/json", ct)
	}
	var snap statsSnapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		t.Fatalf("decoding /stats JSON: %v\nbody: %s", err, body)
	}
	return &snap
}

// ============================================================================
// Tests
// ============================================================================

func TestNewStatsServerFromConfig_OffByDefault(t *testing.T) {
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})
	srv, err := newStatsServerFromConfig(cfg)
	if err != nil {
		t.Fatalf("newStatsServerFromConfig: %v", err)
	}
	if srv != nil {
		srv.shutdown()
		t.Fatal("expected nil stats server when statsListen is unset")
	}

	cfg.Live.StatsListen = "127.0.0.1:0"
	srv, err = newStatsServerFromConfig(cfg)
	if err != nil {
		t.Fatalf("newStatsServerFromConfig with statsListen: %v", err)
	}
	if srv == nil {
		t.Fatal("expected stats server when statsListen is set")
	}
	srv.start()
	defer srv.shutdown()
	if srv.addr() == "" || strings.HasSuffix(srv.addr(), ":0") {
		t.Errorf("addr() = %q, want resolved ephemeral port", srv.addr())
	}
}

func TestStatsEndpoint_SchemaAndValues(t *testing.T) {
	now := time.Now()
	batch := hotBlock(10, 5, 5, now, "/api/item")
	fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})

	srv := newTestStatsServer(t)
	h := startLoopWithStats(t, fake, cfg, srv)
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}

	snap := getSnapshot(t, srv)

	if snap.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", snap.SchemaVersion)
	}
	if snap.Loop.Iterations < 1 {
		t.Errorf("loop.iterations = %d, want >= 1", snap.Loop.Iterations)
	}
	if snap.Loop.SleepS != 0 {
		t.Errorf("loop.sleep_s = %d, want 0", snap.Loop.SleepS)
	}

	if len(snap.Windows) != 1 {
		t.Fatalf("windows len = %d, want 1", len(snap.Windows))
	}
	w := snap.Windows[0]
	if w.Name != "w" {
		t.Errorf("window name = %q, want w", w.Name)
	}
	if w.SizeIPs != 256 {
		t.Errorf("window size_ips = %d, want 256", w.SizeIPs)
	}
	if w.Requests != 256 {
		t.Errorf("window requests = %d, want 256", w.Requests)
	}
	if w.AcceptedTotal != 256 {
		t.Errorf("window accepted_total = %d, want 256", w.AcceptedTotal)
	}
	if w.RejectedByFilterTotal != 0 {
		t.Errorf("window rejected_by_filter_total = %d, want 0", w.RejectedByFilterTotal)
	}
	if w.TopTalkers != nil {
		t.Errorf("top_talkers = %+v, want absent (topTalkers unset)", w.TopTalkers)
	}
	if len(w.ClusterSets) != 1 {
		t.Fatalf("cluster_sets len = %d, want 1", len(w.ClusterSets))
	}
	cs := w.ClusterSets[0]
	if cs.Params.MinSize != 100 || cs.Params.Depth != "24-32" || cs.Params.Threshold != 0.5 {
		t.Errorf("cluster params = %+v, want {100 24-32 0.5}", cs.Params)
	}
	if !cs.UseForJail {
		t.Error("use_for_jail = false, want true")
	}
	if len(cs.DetectedNow) != 1 || cs.DetectedNow[0].CIDR != "10.5.5.0/24" || cs.DetectedNow[0].Count != 256 {
		t.Errorf("detected_now = %+v, want [{10.5.5.0/24 256}]", cs.DetectedNow)
	}

	if snap.Jail.TotalActive != 1 {
		t.Errorf("jail.total_active = %d, want 1", snap.Jail.TotalActive)
	}
	if snap.Jail.Truncated {
		t.Error("jail.active_bans_truncated = true, want false")
	}
	if len(snap.Jail.ActiveBans) != 1 {
		t.Fatalf("jail.active_bans len = %d, want 1", len(snap.Jail.ActiveBans))
	}
	ban := snap.Jail.ActiveBans[0]
	if ban.CIDR != "10.5.5.0/24" || ban.Stage != 1 {
		t.Errorf("active ban = %+v, want CIDR 10.5.5.0/24 stage 1", ban)
	}
	if want := ban.BanStart.Add(10 * time.Minute); !ban.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %v, want ban_start+10m = %v", ban.ExpiresAt, want)
	}
	if len(snap.Jail.Stages) != 5 {
		t.Fatalf("jail.stages len = %d, want 5", len(snap.Jail.Stages))
	}
	if s1 := snap.Jail.Stages[0]; s1.Stage != 1 || s1.BanDuration != "10m0s" || s1.Active != 1 {
		t.Errorf("stage 1 = %+v, want {1 10m0s 1}", s1)
	}

	if snap.Lists.BanFile.Path != cfg.GetBanFile() {
		t.Errorf("lists.ban_file.path = %q, want %q", snap.Lists.BanFile.Path, cfg.GetBanFile())
	}
	if snap.Lists.BanFile.Entries != 1 {
		t.Errorf("lists.ban_file.entries = %d, want 1", snap.Lists.BanFile.Entries)
	}
	if snap.Lists.BanFile.LastWritten.IsZero() {
		t.Error("lists.ban_file.last_written is zero, want set")
	}
	if snap.Lists.JailFile.Path != cfg.GetJailFile() {
		t.Errorf("lists.jail_file.path = %q, want %q", snap.Lists.JailFile.Path, cfg.GetJailFile())
	}
	if snap.Lists.Whitelist.Entries != 0 || snap.Lists.Blacklist.Entries != 0 {
		t.Errorf("lists entries = %d/%d, want 0/0", snap.Lists.Whitelist.Entries, snap.Lists.Blacklist.Entries)
	}

	if !snap.Ingest.Connected {
		t.Error("ingest.connected = false, want true (snapshot taken before drain-close)")
	}
	if snap.Ingest.QueueDepth != 0 {
		t.Errorf("ingest.queue_depth = %d, want 0", snap.Ingest.QueueDepth)
	}
}

func TestBansEndpoint_ByteEqualToBanFile(t *testing.T) {
	now := time.Now()
	batch := hotBlock(10, 5, 5, now, "/api/item")
	fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
	cfg := newLiveConfigWithLists(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	}, nil, []string{"203.0.113.0/24"})

	srv := newTestStatsServer(t)
	h := startLoopWithStats(t, fake, cfg, srv)
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}

	status, header, body := httpGet(t, srv, "/bans")
	if status != http.StatusOK {
		t.Fatalf("GET /bans status = %d, want 200", status)
	}
	if ct := header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("GET /bans Content-Type = %q, want text/plain; charset=utf-8", ct)
	}
	disk, err := os.ReadFile(cfg.GetBanFile())
	if err != nil {
		t.Fatalf("reading ban file: %v", err)
	}
	if !bytes.Equal(body, disk) {
		t.Errorf("/bans body differs from ban file on disk:\n/bans:\n%s\ndisk:\n%s", body, disk)
	}
}

func Test503BeforeFirstSnapshot(t *testing.T) {
	srv := newTestStatsServer(t)
	for _, path := range []string{"/stats", "/bans"} {
		status, header, _ := httpGet(t, srv, path)
		if status != http.StatusServiceUnavailable {
			t.Errorf("GET %s status = %d, want 503", path, status)
		}
		if ra := header.Get("Retry-After"); ra != "5" {
			t.Errorf("GET %s Retry-After = %q, want 5", path, ra)
		}
	}
}

func TestStatsServer_NotFoundAndMethodNotAllowed(t *testing.T) {
	srv := newTestStatsServer(t)
	srv.publish(&statsSnapshot{SchemaVersion: statsSchemaVersion})

	if status, _, _ := httpGet(t, srv, "/nope"); status != http.StatusNotFound {
		t.Errorf("GET /nope status = %d, want 404", status)
	}

	resp, err := http.Post("http://"+srv.addr()+"/stats", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /stats: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /stats status = %d, want 405", resp.StatusCode)
	}
}

// TestStatsEndpoint_ConcurrentReads hammers GET /stats while the loop
// publishes fresh snapshots; the race detector is the oracle for snapshot
// immutability, and every 200 body must decode cleanly.
func TestStatsEndpoint_ConcurrentReads(t *testing.T) {
	now := time.Now()
	batches := [][]ingestor.Request{
		hotBlock(10, 5, 5, now, "/api/item"),
		noiseRequests(now, "/api/item"),
		hotBlock(10, 6, 6, now, "/api/item"),
		noiseRequests(now, "/api/item"),
		hotBlock(10, 7, 7, now, "/api/item"),
	}
	fake := &fakeIngestor{batches: batches, closeAfterDrain: true}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})
	cfg.Live.TopTalkers = 3 // exercise the cached top-talker slices too

	srv := newTestStatsServer(t)
	h := startLoopWithStats(t, fake, cfg, srv)

	hammerDone := make(chan struct{})
	go func() {
		defer close(hammerDone)
		client := &http.Client{Timeout: 2 * time.Second}
		for {
			select {
			case <-h.done:
				return
			default:
			}
			resp, err := client.Get("http://" + srv.addr() + "/stats")
			if err != nil {
				t.Errorf("hammer GET /stats: %v", err)
				return
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Errorf("hammer reading body: %v", err)
				return
			}
			if resp.StatusCode == http.StatusOK {
				var snap statsSnapshot
				if err := json.Unmarshal(body, &snap); err != nil {
					t.Errorf("hammer: /stats JSON did not decode: %v\nbody: %s", err, body)
					return
				}
			}
		}
	}()

	if err := h.wait(10 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}
	select {
	case <-hammerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("hammer goroutine did not stop")
	}
}

func TestStatsServer_LifecycleNoLeak(t *testing.T) {
	fake := &fakeIngestor{} // stays open until Close
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})

	srv := newTestStatsServer(t)
	h := startLoopWithStats(t, fake, cfg, srv)
	h.awaitMessage("Filebeat connected")

	h.cancel()
	if err := h.wait(2 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}

	shutdownDone := make(chan struct{})
	go func() {
		srv.shutdown()
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not return within 3s")
	}

	if _, err := http.Get("http://" + srv.addr() + "/stats"); err == nil {
		t.Error("GET /stats after shutdown succeeded, want connection error")
	}
}

func TestStatsEndpoint_TopTalkers(t *testing.T) {
	now := time.Now()
	var batch []ingestor.Request
	for i := 0; i < 5; i++ {
		batch = append(batch, mkRequest(10, 0, 0, 1, now, "/api/item"))
	}
	for i := 0; i < 3; i++ {
		batch = append(batch, mkRequest(10, 0, 0, 2, now, "/api/item"))
	}
	batch = append(batch, mkRequest(10, 0, 0, 3, now, "/api/item"))

	fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})
	cfg.Live.TopTalkers = 2

	srv := newTestStatsServer(t)
	h := startLoopWithStats(t, fake, cfg, srv)
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}

	snap := getSnapshot(t, srv)
	if len(snap.Windows) != 1 {
		t.Fatalf("windows len = %d, want 1", len(snap.Windows))
	}
	tt := snap.Windows[0].TopTalkers
	if len(tt) != 2 ||
		tt[0].IP != "10.0.0.1" || tt[0].Count != 5 ||
		tt[1].IP != "10.0.0.2" || tt[1].Count != 3 {
		t.Errorf("top_talkers = %+v, want [{10.0.0.1 5} {10.0.0.2 3}]", tt)
	}
}

func TestStatsEndpoint_TopTalkersFieldAbsentWhenDisabled(t *testing.T) {
	now := time.Now()
	batch := hotBlock(10, 5, 5, now, "/api/item")
	fake := &fakeIngestor{batches: [][]ingestor.Request{batch}, closeAfterDrain: true}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	}) // TopTalkers defaults to 0

	srv := newTestStatsServer(t)
	h := startLoopWithStats(t, fake, cfg, srv)
	if err := h.wait(5 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}

	status, _, body := httpGet(t, srv, "/stats")
	if status != http.StatusOK {
		t.Fatalf("GET /stats status = %d, want 200", status)
	}
	if bytes.Contains(body, []byte(`"top_talkers"`)) {
		t.Errorf("/stats contains top_talkers field with topTalkers=0:\n%s", body)
	}
}
