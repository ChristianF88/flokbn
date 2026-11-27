package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/jail"
	"github.com/ChristianF88/flokbn/output"
	"github.com/ChristianF88/flokbn/testutil"
)

const (
	publishExpiredCIDR = "198.51.100.0/24" // stage-1 ban (10m) started 1h ago
	publishActiveCIDR  = "203.0.113.0/24"  // stage-1 ban (10m) started just now
	publishLogFormat   = "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\""
)

// seedPublishJail persists a jail holding one ban that has run out and one
// ban that is still running.
func seedPublishJail(t *testing.T, path string) {
	t.Helper()
	testutil.WriteJailFile(t, path,
		testutil.JailRecord{CIDR: publishExpiredCIDR, Stage: 1, BanStart: time.Now().Add(-time.Hour)},
		testutil.JailRecord{CIDR: publishActiveCIDR, Stage: 1, BanStart: time.Now()},
	)
}

func publishCfg(t *testing.T, dir, logContent string) *config.Config {
	t.Helper()
	logFile := filepath.Join(dir, "access.log")
	if err := os.WriteFile(logFile, []byte(logContent), 0644); err != nil {
		t.Fatalf("writing log: %v", err)
	}
	return &config.Config{
		Global: &config.GlobalConfig{
			JailFile: filepath.Join(dir, "jail.json"),
			BanFile:  filepath.Join(dir, "ban.txt"),
		},
		Static: &config.StaticConfig{LogFile: logFile, LogFormat: publishLogFormat},
		StaticTries: map[string]*config.TrieConfig{
			"t": {
				TrieCommon: config.TrieCommon{
					ClusterArgSets: []config.ClusterArgSet{{MinClusterSize: 100, MinDepth: 24, MaxDepth: 24, MeanSubnetDifference: 0.5}},
					UseForJail:     []bool{true},
				},
			},
		},
	}
}

func banFileCIDRs(t *testing.T, path string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading ban file: %v", err)
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = true
	}
	return out
}

// assertExpiredBanDropped checks the published ban file and the persisted jail
// after a run that detected nothing: the run-out ban must be gone from the ban
// file and still be in the jail as an ended ban (it is the memory a repeat is
// judged by), the running ban must be untouched.
func assertExpiredBanDropped(t *testing.T, cfg *config.Config) {
	t.Helper()
	bans := banFileCIDRs(t, cfg.GetBanFile())
	if bans[publishExpiredCIDR] {
		t.Errorf("ban file republishes expired ban %s: %v", publishExpiredCIDR, bans)
	}
	if !bans[publishActiveCIDR] {
		t.Errorf("ban file lost the still-active ban %s: %v", publishActiveCIDR, bans)
	}

	j, err := jail.Load(cfg.GetJailFile(), jail.DefaultConfig())
	if err != nil {
		t.Fatalf("reloading jail: %v", err)
	}
	now := time.Now()
	present := map[string]bool{}
	for _, r := range j.Records() {
		present[r.CIDR().String()] = true
	}
	active := map[string]bool{}
	for _, b := range j.Active(now) {
		active[b.CIDR.String()] = true
	}
	if !present[publishExpiredCIDR] || active[publishExpiredCIDR] {
		t.Errorf("persisted jail: expired ban %s present=%v active=%v, want present and ended", publishExpiredCIDR, present[publishExpiredCIDR], active[publishExpiredCIDR])
	}
	if !present[publishActiveCIDR] || !active[publishActiveCIDR] {
		t.Errorf("persisted jail: running ban %s present=%v active=%v, want present and active", publishActiveCIDR, present[publishActiveCIDR], active[publishActiveCIDR])
	}
}

// A static run that detects nothing must still drop the bans that ran out
// from the ban file: whether a ban is active is computed from the time of the
// run, never read from a flag an earlier run left on disk.
func TestStaticNoDetectionsExpiresBans(t *testing.T) {
	// Two requests, far below minClusterSize: no detections.
	logContent := `192.0.2.1 - - [01/Jan/2023:12:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "a"
192.0.2.2 - - [01/Jan/2023:12:00:01 +0000] "GET / HTTP/1.1" 200 1 "-" "b"
`
	runs := map[string]func(*config.Config) error{
		"Static": func(cfg *config.Config) error { _, err := Static(cfg); return err },
		"StaticWithRequests": func(cfg *config.Config) error {
			_, _, err := StaticWithRequests(cfg)
			return err
		},
	}
	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := publishCfg(t, dir, logContent)
			seedPublishJail(t, cfg.GetJailFile())
			if err := run(cfg); err != nil {
				t.Fatalf("run failed: %v", err)
			}
			assertExpiredBanDropped(t, cfg)
		})
	}
}

// An empty log used to return before the jail/ban publish step, so run-out
// bans stayed published and whitelist/blacklist edits were not picked up.
func TestStaticEmptyLogStillPublishes(t *testing.T) {
	runs := map[string]func(*config.Config) (*output.JSONOutput, error){
		"Static": Static,
		"StaticWithRequests": func(cfg *config.Config) (*output.JSONOutput, error) {
			out, _, err := StaticWithRequests(cfg)
			return out, err
		},
	}
	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := publishCfg(t, dir, "")
			seedPublishJail(t, cfg.GetJailFile())
			blacklist := filepath.Join(dir, "blacklist.txt")
			if err := os.WriteFile(blacklist, []byte("192.0.2.0/24\n"), 0644); err != nil {
				t.Fatal(err)
			}
			cfg.Global.Blacklist = blacklist

			out, err := run(cfg)
			if err != nil {
				t.Fatalf("run failed: %v", err)
			}
			hasEmptyWarning := false
			for _, w := range out.Warnings {
				if w.Type == "empty_logfile" {
					hasEmptyWarning = true
				}
			}
			if !hasEmptyWarning {
				t.Error("missing empty_logfile warning")
			}
			assertExpiredBanDropped(t, cfg)
			if bans := banFileCIDRs(t, cfg.GetBanFile()); !bans["192.0.2.0/24"] {
				t.Errorf("manual blacklist edit not published on an empty log: %v", bans)
			}
		})
	}
}

// Without a configured jail/ban file an empty log must stay side-effect free.
func TestStaticEmptyLogWithoutJailWritesNothing(t *testing.T) {
	dir := t.TempDir()
	cfg := publishCfg(t, dir, "")
	cfg.Global = &config.GlobalConfig{}
	if _, err := Static(cfg); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("empty-log run without jail config created files: %v", entries)
	}
}

// A run with nothing to add and nothing expired must not create or rewrite the
// jail file (the ban file is always written).
func TestStaticNoDetectionsLeavesUnchangedJailAlone(t *testing.T) {
	dir := t.TempDir()
	cfg := publishCfg(t, dir, "192.0.2.1 - - [01/Jan/2023:12:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"a\"\n")
	if _, err := Static(cfg); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if _, err := os.Stat(cfg.GetJailFile()); !os.IsNotExist(err) {
		t.Errorf("jail file created by a run with no detections and no expiry (stat err=%v)", err)
	}
	if _, err := os.Stat(cfg.GetBanFile()); err != nil {
		t.Errorf("ban file not written: %v", err)
	}
}

// TestStaticBanFileListsRunningBansMerged: the ban file is the short list for
// a firewall. Of everything the jail holds it lists only the bans that are
// running, a range inside another one once (as the wider range), and
// neighbouring ranges joined. The jail file keeps every record.
func TestStaticBanFileListsRunningBansMerged(t *testing.T) {
	dir := t.TempDir()
	cfg := publishCfg(t, dir, "")
	now := time.Now()
	running, ended := now.Add(-time.Minute), now.Add(-time.Hour)
	testutil.WriteJailFile(t, cfg.GetJailFile(),
		testutil.JailRecord{CIDR: "10.0.0.0/16", Stage: 2, BanStart: running},     // 4 hours
		testutil.JailRecord{CIDR: "10.0.5.0/24", Stage: 3, BanStart: running},     // inside the /16
		testutil.JailRecord{CIDR: "10.0.5.7/32", Stage: 5, BanStart: running},     // inside both
		testutil.JailRecord{CIDR: "10.9.0.0/24", Stage: 1, BanStart: ended},       // ran out
		testutil.JailRecord{CIDR: "192.0.2.0/25", Stage: 2, BanStart: running},    // two halves ...
		testutil.JailRecord{CIDR: "192.0.2.128/25", Stage: 3, BanStart: running},  // ... of one /24
		testutil.JailRecord{CIDR: "198.51.100.0/24", Stage: 1, BanStart: ended},   // ran out, with ...
		testutil.JailRecord{CIDR: "198.51.100.9/32", Stage: 4, BanStart: running}, // ... a running ban inside
	)
	if _, err := Static(cfg); err != nil {
		t.Fatalf("run failed: %v", err)
	}

	got := banFileCIDRs(t, cfg.GetBanFile())
	want := []string{"10.0.0.0/16", "192.0.2.0/24", "198.51.100.9/32"}
	if len(got) != len(want) {
		t.Errorf("ban file lists %d ranges, want %d: %v", len(got), len(want), got)
	}
	for _, c := range want {
		if !got[c] {
			t.Errorf("ban file lacks %s: %v", c, got)
		}
	}

	j, err := jail.Load(cfg.GetJailFile(), jail.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if j.Len() != 8 {
		t.Errorf("%d records in the jail file, want all 8", j.Len())
	}
}
