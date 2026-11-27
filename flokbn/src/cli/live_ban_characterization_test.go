package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/jail"
	"github.com/ChristianF88/flokbn/logging"
	"github.com/ChristianF88/flokbn/testutil"
)

// Characterization of the live ban pipeline: what one iteration and one idle
// heartbeat do to the jail and the ban file, pinned as observed. The
// whitelist -> jail -> publish sequence is shared with static mode
// (analysis.UpdateBans); these tests exist so that restructuring the loop
// cannot move WHEN a detection starts, keeps or escalates a ban.

// seedPrisoner is one record written into the jail file before the loop
// starts. age is how long ago its ban started; whether the ban is still
// running follows from that and the duration of its stage.
type seedPrisoner struct {
	cell int // stage - 1
	cidr string
	age  time.Duration
}

// seedJail writes a jail holding the given records.
func seedJail(t *testing.T, path string, now time.Time, prisoners []seedPrisoner) {
	t.Helper()
	records := make([]testutil.JailRecord, len(prisoners))
	for i, p := range prisoners {
		records[i] = testutil.JailRecord{CIDR: p.cidr, Stage: p.cell + 1, BanStart: now.Add(-p.age)}
	}
	testutil.WriteJailFile(t, path, records...)
}

// jailDump renders the jail file as sorted lines
// "stage <n> <cidr> active|expired start=old|new". "old" means the ban
// started before since (a seeded start), "new" that the loop started the ban
// at or after it.
func jailDump(t *testing.T, path string, since time.Time) []string {
	t.Helper()
	j, err := jail.Load(path, jail.DefaultConfig())
	if err != nil {
		t.Fatalf("reading jail file %s: %v", path, err)
	}
	active := map[string]bool{}
	for _, b := range j.Active(time.Now()) {
		active[b.CIDR.String()] = true
	}
	var lines []string
	for _, r := range testutil.JailRecords(t, j.Encode()) {
		state := "expired"
		if active[r.CIDR] {
			state = "active"
		}
		start := "new"
		if r.BanStart.Before(since) {
			start = "old"
		}
		lines = append(lines, fmt.Sprintf("stage %d %s %s start=%s", r.Stage, r.CIDR, state, start))
	}
	sort.Strings(lines)
	return lines
}

// banFileSections returns the ban file's active-ban section and its manual
// blacklist section, each sorted.
func banFileSections(t *testing.T, path string) (bans, blacklist []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading ban file %s: %v", path, err)
	}
	inBlacklist := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "# Manual blacklist entries"):
			inBlacklist = true
		case strings.HasPrefix(line, "#"):
		case inBlacklist:
			blacklist = append(blacklist, line)
		default:
			bans = append(bans, line)
		}
	}
	sort.Strings(bans)
	sort.Strings(blacklist)
	return bans, blacklist
}

// intAttrs returns the named integer attributes of a log record as
// "key=value" strings, in the order asked for.
func intAttrs(t *testing.T, ev logEvent, keys ...string) []string {
	t.Helper()
	attrs := recordAttrs(ev.rec)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		v, ok := attrs[k]
		if !ok {
			t.Fatalf("%q record has no attr %q (attrs: %v)", ev.rec.Message, k, attrs)
		}
		out = append(out, fmt.Sprintf("%s=%v", k, v.Any()))
	}
	return out
}

func assertLines(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s:\n got:\n  %s\nwant:\n  %s", what, strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// stepUntil releases one ReadBatch and returns the first record with the
// given message, together with every record logged before it.
func (g *gatedIngestor) stepUntil(t *testing.T, h *loopHarness, msg string) (logEvent, []logEvent) {
	t.Helper()
	select {
	case g.gate <- struct{}{}:
	case <-time.After(10 * time.Second):
		t.Fatal("loop never asked for the next batch")
	}
	var before []logEvent
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev := <-h.events:
			if ev.rec.Message == msg {
				return ev, before
			}
			before = append(before, ev)
		case <-deadline:
			t.Fatalf("timed out waiting for %q log record", msg)
		}
	}
}

// uaRequest is a single request carrying the given User-Agent.
func uaRequest(o1, o2, o3, o4 byte, ts time.Time, ua string) accesslog.Request {
	r := mkRequest(o1, o2, o3, o4, ts, "/")
	r.UserAgent = ua
	return r
}

const day = 24 * time.Hour

// TestLiveBanPipeline_IterationCharacterization runs one iteration over a
// jail seeded with every kind of prisoner the escalation rules distinguish,
// with CIDR and User-Agent lists in play.
func TestLiveBanPipeline_IterationCharacterization(t *testing.T) {
	now := time.Now()

	var batch []accesslog.Request
	for _, hot := range [][3]byte{
		{10, 5, 5},    // seeded, ban ran out: next stage
		{10, 6, 6},    // new; one of its IPs is UA-whitelisted
		{10, 8, 8},    // seeded, ban still running: untouched
		{10, 9, 9},    // around a seeded /25 whose ban is running: its own ladder
		{10, 10, 10},  // around a seeded /25 whose ban ran out: one stage up, the /25 with it
		{10, 20, 5},   // inside a seeded /16 whose ban is running: ignored
		{10, 21, 5},   // inside a seeded /16 whose ban ran out: a new offender
		{192, 168, 7}, // fully whitelisted
		{172, 16, 3},  // overlaps a whitelisted /32
	} {
		batch = append(batch, hotBlock(hot[0], hot[1], hot[2], now, "/api/item")...)
	}
	batch = append(batch, noiseRequests(now, "/api/item")...)
	batch = append(batch,
		uaRequest(203, 0, 113, 9, now, "BadBot/1.0"),   // forced /32
		uaRequest(192, 168, 1, 1, now, "BadBot/1.0"),   // forced /32 inside the whitelist
		uaRequest(10, 6, 6, 77, now, "GoodBot/1.0"),    // immunized /32 inside a detected range
		uaRequest(198, 51, 100, 5, now, "GoodBot/1.0"), // immunized /32 inside the manual blacklist
	)

	ing := newGatedIngestor(batch)
	cfg := newLiveConfigWithUALists(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	},
		[]string{"192.168.0.0/16", "172.16.3.7/32"},    // CIDR whitelist
		[]string{"198.51.100.0/24", "192.168.99.0/24"}, // manual blacklist
		[]string{"GoodBot/1.0"},
		[]string{"BadBot/1.0"},
	)
	seedJail(t, cfg.GetJailFile(), now, []seedPrisoner{
		{cell: 0, cidr: "10.5.5.0/24", age: time.Hour},
		{cell: 0, cidr: "10.7.7.0/24", age: time.Hour}, // ran out, not seen again
		{cell: 1, cidr: "10.8.8.0/24", age: time.Minute},
		{cell: 0, cidr: "10.9.9.0/25", age: time.Minute},
		{cell: 1, cidr: "10.10.10.0/25", age: 5 * time.Hour},
		{cell: 2, cidr: "10.20.0.0/16", age: time.Hour},
		{cell: 1, cidr: "10.21.0.0/16", age: 5 * time.Hour},
		{cell: 0, cidr: "10.99.0.0/24", age: 400 * day},      // beyond the retention
		{cell: 0, cidr: "192.168.50.0/24", age: time.Minute}, // banned before it was whitelisted
	})

	h := startLoop(t, ing, cfg)
	ev, before := ing.stepUntil(t, h, "iteration")

	assertLines(t, "iteration record",
		intAttrs(t, ev, "detected", "jailed", "pruned", "active_bans", "ban_file_written", "jail_file_written"),
		[]string{"detected=9", "jailed=10", "pruned=1", "active_bans=23", "ban_file_written=true", "jail_file_written=true"})

	var dropped []string
	for _, e := range before {
		if e.rec.Message == whitelistAppliedMsg {
			dropped = append(dropped, intAttrs(t, e, "count")...)
		}
	}
	assertLines(t, "whitelist warning", dropped, []string{"count=1"})

	assertLines(t, "jail file", jailDump(t, cfg.GetJailFile(), now), []string{
		"stage 1 10.21.5.0/24 active start=new",
		"stage 1 10.6.6.0/24 active start=new",
		"stage 1 10.7.7.0/24 expired start=old",
		"stage 1 10.9.9.0/24 active start=new",
		"stage 1 10.9.9.0/25 active start=old",
		"stage 1 172.16.3.0/24 active start=new",
		"stage 1 192.168.1.1/32 active start=new",
		"stage 1 192.168.50.0/24 active start=old",
		"stage 1 203.0.113.9/32 active start=new",
		"stage 2 10.21.0.0/16 expired start=old",
		"stage 2 10.5.5.0/24 active start=new",
		"stage 2 10.8.8.0/24 active start=old",
		"stage 3 10.10.10.0/24 active start=new",
		"stage 3 10.10.10.0/25 active start=new",
		"stage 3 10.20.0.0/16 active start=old",
	})

	bans, blacklist := banFileSections(t, cfg.GetBanFile())
	assertLines(t, "ban file, active bans", bans, []string{
		"10.10.10.0/24",
		"10.20.0.0/16",
		"10.21.5.0/24",
		"10.5.5.0/24",
		// 10.6.6.0/24 around the UA-whitelisted 10.6.6.77
		"10.6.6.0/26",
		"10.6.6.128/25",
		"10.6.6.64/29",
		"10.6.6.72/30",
		"10.6.6.76/32",
		"10.6.6.78/31",
		"10.6.6.80/28",
		"10.6.6.96/27",
		"10.8.8.0/24",
		"10.9.9.0/24",
		// 172.16.3.0/24 around the whitelisted 172.16.3.7
		"172.16.3.0/30",
		"172.16.3.128/25",
		"172.16.3.16/28",
		"172.16.3.32/27",
		"172.16.3.4/31",
		"172.16.3.6/32",
		"172.16.3.64/26",
		"172.16.3.8/29",
		"203.0.113.9/32",
	})
	assertLines(t, "ban file, manual blacklist", blacklist, []string{
		// 198.51.100.0/24 around the UA-whitelisted 198.51.100.5
		"198.51.100.0/30",
		"198.51.100.128/25",
		"198.51.100.16/28",
		"198.51.100.32/27",
		"198.51.100.4/32",
		"198.51.100.6/31",
		"198.51.100.64/26",
		"198.51.100.8/29",
	})
	if got := ev.snap.Jail.TotalActive; got != 13 {
		t.Errorf("jail.total_active = %d, want 13 (the jail counts its records with a running ban, nested ones each, before the whitelist)", got)
	}
}

// TestLiveBanPipeline_QuietIterationExpiresBans: an iteration that detects
// nothing publishes only the bans that are still running; a ban that ran out
// stays in the jail as an ended record. The first iteration writes both
// files once, a second quiet one writes nothing.
func TestLiveBanPipeline_QuietIterationExpiresBans(t *testing.T) {
	now := time.Now()
	ing := newGatedIngestor(noiseRequests(now, "/api/item"), noiseRequests(now, "/api/item"))
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})
	seedJail(t, cfg.GetJailFile(), now, []seedPrisoner{
		{cell: 0, cidr: "10.7.7.0/24", age: time.Hour},
		{cell: 1, cidr: "10.8.8.0/24", age: time.Minute},
	})
	wantJail := []string{
		"stage 1 10.7.7.0/24 expired start=old",
		"stage 2 10.8.8.0/24 active start=old",
	}

	h := startLoop(t, ing, cfg)

	ev, _ := ing.stepUntil(t, h, "iteration")
	assertLines(t, "first iteration record",
		intAttrs(t, ev, "detected", "jailed", "pruned", "active_bans", "ban_file_written", "jail_file_written"),
		[]string{"detected=0", "jailed=0", "pruned=0", "active_bans=1", "ban_file_written=true", "jail_file_written=true"})
	assertLines(t, "jail file", jailDump(t, cfg.GetJailFile(), now), wantJail)
	bans, _ := banFileSections(t, cfg.GetBanFile())
	assertLines(t, "ban file", bans, []string{"10.8.8.0/24"})

	ev, _ = ing.stepUntil(t, h, "iteration")
	assertLines(t, "second iteration record",
		intAttrs(t, ev, "jailed", "active_bans", "ban_file_written", "jail_file_written"),
		[]string{"jailed=0", "active_bans=1", "ban_file_written=false", "jail_file_written=false"})
	assertLines(t, "jail file after the second iteration", jailDump(t, cfg.GetJailFile(), now), wantJail)
}

// TestLiveBanPipeline_HeartbeatCharacterization follows two bans through the
// end of their first stage, which they reach a few seconds into the test:
// left alone by an iteration and by heartbeats while they run, dropped from
// the ban file by the heartbeat after they ran out, and banned again only by
// the next iteration - not by a heartbeat, although the window still holds
// the detected range and the forced IP is still tracked.
func TestLiveBanPipeline_HeartbeatCharacterization(t *testing.T) {
	now := time.Now()
	hot := append(hotBlock(10, 5, 5, now, "/api/item"), uaRequest(203, 0, 113, 9, now, "BadBot/1.0"))
	ing := newGatedIngestor(hot, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		noiseRequests(now, "/api/item"))
	cfg := newLiveConfigWithUALists(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	}, nil, nil, nil, []string{"BadBot/1.0"})
	// Both bans are in their first stage (10 minutes) with 6 seconds left.
	left := 6 * time.Second
	seedJail(t, cfg.GetJailFile(), now, []seedPrisoner{
		{cell: 0, cidr: "10.5.5.0/24", age: 10*time.Minute - left},
		{cell: 0, cidr: "203.0.113.9/32", age: 10*time.Minute - left},
	})
	banPath, jailPath := cfg.GetBanFile(), cfg.GetJailFile()

	h := startLoop(t, ing, cfg)

	// Iteration: both are detected while banned, which changes nothing. The
	// files are written because this run has not written them yet.
	ev, _ := ing.stepUntil(t, h, "iteration")
	assertLines(t, "iteration record",
		intAttrs(t, ev, "detected", "jailed", "active_bans", "ban_file_written", "jail_file_written"),
		[]string{"detected=1", "jailed=2", "active_bans=2", "ban_file_written=true", "jail_file_written=true"})
	running := []string{
		"stage 1 10.5.5.0/24 active start=old",
		"stage 1 203.0.113.9/32 active start=old",
	}
	assertLines(t, "jail file after the iteration", jailDump(t, jailPath, now), running)
	bans, _ := banFileSections(t, banPath)
	assertLines(t, "ban file after the iteration", bans, []string{"10.5.5.0/24", "203.0.113.9/32"})
	ban1, jail1 := statFile(t, banPath), statFile(t, jailPath)

	// Heartbeat while the bans run: nothing is written.
	ev, _ = ing.stepUntil(t, h, "heartbeat")
	assertLines(t, "heartbeat record while the bans run",
		intAttrs(t, ev, "expired", "active_bans", "ban_file_written"),
		[]string{"expired=0", "active_bans=2", "ban_file_written=false"})
	if !ban1.untouched(statFile(t, banPath)) || !jail1.untouched(statFile(t, jailPath)) {
		t.Errorf("a heartbeat that changed nothing rewrote the ban or jail file")
	}
	if got := ev.snap.Jail.TotalActive; got != 2 {
		t.Errorf("jail.total_active = %d, want 2", got)
	}

	// Heartbeats until the bans run out (about one per second).
	expired := false
	for i := 0; i < 14 && !expired; i++ {
		ev, _ = ing.stepUntil(t, h, "heartbeat")
		expired = recordAttrs(ev.rec)["expired"].Int64() > 0
	}
	if !expired {
		t.Fatal("no heartbeat saw the bans run out")
	}
	assertLines(t, "heartbeat record after the bans ran out",
		intAttrs(t, ev, "expired", "active_bans", "ban_file_written"),
		[]string{"expired=2", "active_bans=0", "ban_file_written=true"})
	// The window (24h) still holds 10.5.5.0/24 and 203.0.113.9 is still a
	// tracked blacklisted-UA IP, but a heartbeat never jails.
	if detected := detectedNow(ev.snap); len(detected) != 1 || detected[0].CIDR != "10.5.5.0/24" {
		t.Errorf("heartbeat detected_now = %+v, want the range still in the window", detected)
	}
	ranOut := []string{
		"stage 1 10.5.5.0/24 expired start=old",
		"stage 1 203.0.113.9/32 expired start=old",
	}
	assertLines(t, "jail file after the bans ran out", jailDump(t, jailPath, now), ranOut)
	bans, _ = banFileSections(t, banPath)
	assertLines(t, "ban file after the bans ran out", bans, nil)
	// A ban that ran out leaves its record as it is: the jail file is not
	// rewritten for it.
	jail2 := statFile(t, jailPath)
	if !jail1.untouched(jail2) {
		t.Errorf("the jail file was rewritten although no record changed")
	}

	// A heartbeat with nothing to do does not bring back a deleted jail file.
	if err := os.Remove(jailPath); err != nil {
		t.Fatalf("removing jail file: %v", err)
	}
	ev, _ = ing.stepUntil(t, h, "heartbeat")
	assertLines(t, "heartbeat record after the bans ran out",
		intAttrs(t, ev, "expired", "active_bans", "ban_file_written"),
		[]string{"expired=0", "active_bans=0", "ban_file_written=false"})
	if !fileMissing(jailPath) {
		t.Errorf("a heartbeat with no jail change rewrote the deleted jail file")
	}

	// The next iteration re-detects both and bans them again at the next
	// stage, whatever the batch holds: the range is still in the window, the
	// IP still tracked.
	ing.mu.Lock()
	ing.batches = ing.batches[len(ing.batches)-1:]
	ing.mu.Unlock()
	beforeSecond := time.Now()
	ev, _ = ing.stepUntil(t, h, "iteration")
	assertLines(t, "second iteration record",
		intAttrs(t, ev, "detected", "jailed", "active_bans", "ban_file_written", "jail_file_written"),
		[]string{"detected=1", "jailed=2", "active_bans=2", "ban_file_written=true", "jail_file_written=true"})
	assertLines(t, "jail file after the second iteration", jailDump(t, jailPath, beforeSecond), []string{
		"stage 2 10.5.5.0/24 active start=new",
		"stage 2 203.0.113.9/32 active start=new",
	})
	bans, _ = banFileSections(t, banPath)
	assertLines(t, "ban file after the second iteration", bans, []string{"10.5.5.0/24", "203.0.113.9/32"})
	if got := statFile(t, jailPath).content; got == jail2.content {
		t.Errorf("jail file content did not change with the new bans")
	}
}

// BenchmarkLiveLoopIteration measures one full loop iteration (window update,
// two cluster sets, jail update, ban composition, change-detected file
// writes) on a steady state: the same ranges are detected every time, so
// after the first iteration nothing is written to disk.
func BenchmarkLiveLoopIteration(b *testing.B) {
	for _, bc := range []struct {
		name  string
		stats bool
	}{{"stats_off", false}, {"stats_on", true}} {
		b.Run(bc.name, func(b *testing.B) {
			now := time.Now()
			var batch []accesslog.Request
			for i := 0; i < 8; i++ {
				batch = append(batch, hotBlock(10, byte(i+1), 5, now, "/api/item")...)
			}
			for i := 0; i < 40; i++ {
				batch = append(batch, mkRequest(byte(60+i), 1, 2, 3, now, "/"))
			}
			batches := make([][]accesslog.Request, b.N)
			for i := range batches {
				batches[i] = batch
			}

			dir := b.TempDir()
			var whitelist strings.Builder
			for i := 0; i < 50; i++ {
				fmt.Fprintf(&whitelist, "192.168.%d.0/24\n", i)
			}
			whitelistPath := dir + "/whitelist.txt"
			if err := os.WriteFile(whitelistPath, []byte(whitelist.String()), 0644); err != nil {
				b.Fatal(err)
			}
			stc := &config.SlidingTrieConfig{
				SlidingWindowMaxTime: time.Hour,
				SlidingWindowMaxSize: 20000,
				TrieCommon: config.TrieCommon{
					ClusterArgSets: []config.ClusterArgSet{
						testClusterArgSet(),
						{MinClusterSize: 1000, MinDepth: 8, MaxDepth: 16, MeanSubnetDifference: 0.5},
					},
					UseForJail: []bool{true, false},
				},
			}
			cfg := &config.Config{
				Global: &config.GlobalConfig{
					JailFile:  dir + "/jail.json",
					BanFile:   dir + "/ban.txt",
					Whitelist: whitelistPath,
				},
				Live:      &config.LiveConfig{Port: "0"},
				LiveTries: map[string]*config.SlidingTrieConfig{"w": stc},
			}
			// 200 running bans the loop carries along.
			records := make([]testutil.JailRecord, 200)
			for i := range records {
				records[i] = testutil.JailRecord{CIDR: fmt.Sprintf("172.20.%d.0/24", i), Stage: 3, BanStart: now}
			}
			testutil.WriteJailFile(b, cfg.GetJailFile(), records...)

			var srv *statsServer
			if bc.stats {
				srv = &statsServer{}
			}
			logger, err := logging.New(io.Discard, "info", "text")
			if err != nil {
				b.Fatal(err)
			}
			fake := &fakeIngestor{batches: batches, closeAfterDrain: true}

			b.ReportAllocs()
			b.ResetTimer()
			if err := runLiveLoop(context.Background(), fake, cfg, logger, srv); err != nil {
				b.Fatal(err)
			}
		})
	}
}
