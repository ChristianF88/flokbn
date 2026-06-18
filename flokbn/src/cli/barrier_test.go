package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// flokbnBin is the path to the binary built once for the whole cli test suite.
// CFG-01's barrier returns cli.Exit("", 1), which triggers os.Exit(1) INSIDE
// App.Run (urfave/cli's default HandleExitCoder). An in-process App.Run test
// would therefore kill the test process — so every barrier-firing test runs the
// BUILT BINARY as a subprocess via os/exec and asserts exit code, stderr, and
// side effects. The binary is built in the FOREGROUND in TestMain.
var flokbnBin string

func TestMain(m *testing.M) {
	// Build under the package directory (the test working directory), not the
	// system temp dir: some sandboxes mount /tmp noexec, which would make the
	// freshly built binary unrunnable.
	dir, err := os.MkdirTemp(".", "flokbn-bin")
	if err != nil {
		panic("mkdtemp: " + err.Error())
	}
	flokbnBin, err = filepath.Abs(filepath.Join(dir, "flokbn"))
	if err != nil {
		os.RemoveAll(dir)
		panic("abs: " + err.Error())
	}
	// The test working directory is the cli package (a library). Build the main
	// package at the module root (the parent directory) so the artifact is an
	// executable, not an ar archive.
	build := exec.Command("go", "build", "-o", flokbnBin, "..")
	if out, err := build.CombinedOutput(); err != nil {
		os.Stderr.Write(out)
		os.RemoveAll(dir)
		panic("go build: " + err.Error())
	}
	// Some environments produce a build artifact without the executable bit;
	// ensure it is runnable before any subprocess test execs it.
	if err := os.Chmod(flokbnBin, 0o755); err != nil {
		os.RemoveAll(dir)
		panic("chmod bin: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// runFlokbn runs the built binary with args, returning stdout, stderr and the
// process exit code. A timeout guards against any path that would block (e.g. a
// TUI that managed to enter its loop, or a live mode that reached Accept).
func runFlokbn(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(flokbnBin, args...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", flokbnBin, err)
	}
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return out.String(), errb.String(), ee.ExitCode()
			}
			t.Fatalf("run %s: %v", flokbnBin, err)
		}
		return out.String(), errb.String(), 0
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("subprocess timed out (did not exit at the barrier)\nstdout:\n%s\nstderr:\n%s", out.String(), errb.String())
	}
	return "", "", 0
}

// writeFile writes content into dir/name and returns the absolute path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

const sampleLogLine = `192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /test HTTP/1.1" 200 100 "-" "Mozilla/5.0" "192.168.1.1"` + "\n"

// staticConfig builds a static config with the given trie body, wiring absolute
// paths for logFile/jail/ban (and plotPath when nonempty).
func staticConfig(t *testing.T, dir, trieBody, plotPath string) string {
	t.Helper()
	logFile := writeFile(t, dir, "access.log", sampleLogLine)
	jailFile := filepath.Join(dir, "jail.json")
	banFile := filepath.Join(dir, "ban.txt")
	plotLine := ""
	if plotPath != "" {
		plotLine = "plotPath = \"" + plotPath + "\"\n"
	}
	body := `
[global]
jailFile = "` + jailFile + `"
banFile = "` + banFile + `"

[static]
logFile = "` + logFile + `"
logFormat = "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%^\""
` + plotLine + `
[static.t]
` + trieBody + `
`
	return writeFile(t, dir, "config.toml", body)
}

// TestBarrierStderrExactness: static --config with a bad startTime exits 1 and
// stderr is EXACTLY the enumerated report (header + 1 numbered line + trailing
// newline) — no "flokbn:" prefix line, no duplicate block.
func TestBarrierStderrExactness(t *testing.T) {
	dir := t.TempDir()
	cfg := staticConfig(t, dir, `startTime = "2026-02-04T12:00:0"`, "")

	stdout, stderr, code := runFlokbn(t, "static", "--config", cfg)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstderr:\n%s", code, stderr)
	}
	want := "configuration errors (1):\n" +
		`1. [static.t] invalid startTime "2026-02-04T12:00:0": want RFC3339 (e.g. 2025-01-01T00:00:00Z)` + "\n"
	if stderr != want {
		t.Errorf("stderr not exact.\nwant:\n%q\ngot:\n%q", want, stderr)
	}
	if strings.Contains(stderr, "flokbn:") {
		t.Errorf("stderr must not carry the flokbn: prefix line:\n%s", stderr)
	}
	if stdout != "" {
		t.Errorf("expected no stdout (no analysis), got:\n%s", stdout)
	}
}

// TestBarrierGatesPlot: a bad startTime with a VALID plotPath under tmp must
// stop at the barrier, NOT plot-path validation, so the plot file is never
// written. POSITIVE CONTROL: the same config with a valid startTime exits 0 and
// the plot file IS written — so the absence in the negative case is attributable
// to the barrier.
func TestBarrierGatesPlot(t *testing.T) {
	// Negative: bad startTime, valid plot dir.
	dirN := t.TempDir()
	plotN := filepath.Join(dirN, "heatmap.html")
	cfgN := staticConfig(t, dirN, `startTime = "bad-ts"`, plotN)
	if _, _, code := runFlokbn(t, "static", "--config", cfgN); code != 1 {
		t.Fatalf("negative: expected exit 1, got %d", code)
	}
	if _, err := os.Stat(plotN); !os.IsNotExist(err) {
		t.Errorf("negative: plot file should NOT exist (barrier should have stopped before plotting)")
	}

	// Positive control: same shape, valid startTime, exits 0, plot exists.
	dirP := t.TempDir()
	plotP := filepath.Join(dirP, "heatmap.html")
	cfgP := staticConfig(t, dirP, `startTime = "2025-01-01T00:00:00Z"`, plotP)
	if stdout, stderr, code := runFlokbn(t, "static", "--config", cfgP); code != 0 {
		t.Fatalf("positive: expected exit 0, got %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if _, err := os.Stat(plotP); err != nil {
		t.Errorf("positive control: plot file should exist after a clean run: %v", err)
	}
}

// TestBarrierGatesBanFile: a bad startTime with a jail-emitting cluster set must
// stop at the barrier before any ban-file write. POSITIVE CONTROL: valid
// timestamps on the same config DO create the ban file.
func TestBarrierGatesBanFile(t *testing.T) {
	trie := func(ts string) string {
		return ts + "\nclusterArgSets = [[1, 0, 32, 1.0]]\nuseForJail = [true]"
	}

	// Negative: bad startTime; ban file must not be created.
	dirN := t.TempDir()
	cfgN := staticConfig(t, dirN, trie(`startTime = "bad-ts"`), "")
	banN := filepath.Join(dirN, "ban.txt")
	if _, _, code := runFlokbn(t, "static", "--config", cfgN); code != 1 {
		t.Fatalf("negative: expected exit 1, got %d", code)
	}
	if _, err := os.Stat(banN); !os.IsNotExist(err) {
		t.Errorf("negative: ban file should NOT exist (barrier should have stopped before ban write)")
	}

	// Positive control: valid startTime; ban file IS created.
	dirP := t.TempDir()
	cfgP := staticConfig(t, dirP, trie(`startTime = "2025-01-01T00:00:00Z"`), "")
	banP := filepath.Join(dirP, "ban.txt")
	if stdout, stderr, code := runFlokbn(t, "static", "--config", cfgP); code != 0 {
		t.Fatalf("positive: expected exit 0, got %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if _, err := os.Stat(banP); err != nil {
		t.Errorf("positive control: ban file should exist after a clean jail run: %v", err)
	}
}

// TestBarrierGatesTUI: static --config --tui with a bad startTime exits 1
// synchronously with the report on stderr, proving it never entered the tview
// loop (the timeout in runFlokbn would otherwise fire).
func TestBarrierGatesTUI(t *testing.T) {
	dir := t.TempDir()
	cfg := staticConfig(t, dir, `startTime = "bad-ts"`, "")
	stdout, stderr, code := runFlokbn(t, "static", "--config", cfg, "--tui")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "[static.t] invalid startTime") {
		t.Errorf("expected report on stderr, got:\n%s", stderr)
	}
}

// TestBarrierGatesLiveBind: live --config with valid required fields but a bad
// [live.<win>] startTime exits 1 with the report, and NEITHER the ingest-bind
// log ("starting live loop") NOR the stats-bind log ("stats server listening")
// appears — a deterministic, no-network proof that neither listener was bound.
// A statsListen is set so BOTH binds are covered.
func TestBarrierGatesLiveBind(t *testing.T) {
	dir := t.TempDir()
	jailFile := filepath.Join(dir, "jail.json")
	banFile := filepath.Join(dir, "ban.txt")
	body := `
[global]
jailFile = "` + jailFile + `"
banFile = "` + banFile + `"

[live]
port = "5045"
statsListen = "127.0.0.1:0"

[live.win]
slidingWindowMaxTime = "1m"
slidingWindowMaxSize = 1000
clusterArgSets = [[1, 0, 32, 1.0]]
useForJail = [true]
startTime = "bad-ts"
`
	cfg := writeFile(t, dir, "live.toml", body)
	stdout, stderr, code := runFlokbn(t, "live", "--config", cfg)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "[live.win] invalid startTime") {
		t.Errorf("expected live report on stderr, got:\n%s", stderr)
	}
	combined := stdout + stderr
	if strings.Contains(combined, "starting live loop") {
		t.Errorf("ingest bind must NOT happen when diagnostics are non-empty:\n%s", combined)
	}
	if strings.Contains(combined, "stats server listening") {
		t.Errorf("stats bind must NOT happen when diagnostics are non-empty:\n%s", combined)
	}
}

// TestBarrierGatesFlagsRange: static flags mode with startTime > endTime exits 1
// via the barrier (both parse as zone-less flexible times => offset-equal =>
// the range check fires) and produces NO analysis output on stdout. Previously
// this was an analysis-time warning with analysis still running.
func TestBarrierGatesFlagsRange(t *testing.T) {
	dir := t.TempDir()
	logFile := writeFile(t, dir, "access.log", sampleLogLine)
	stdout, stderr, code := runFlokbn(t, "static",
		"--logfile", logFile,
		"--startTime", "2025-12-01",
		"--endTime", "2025-01-01")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "is before startTime") {
		t.Errorf("expected range diagnostic on stderr, got:\n%s", stderr)
	}
	if strings.Contains(stdout, "\"tries\"") || strings.Contains(stdout, "totalRequests") {
		t.Errorf("expected no analysis JSON on stdout, got:\n%s", stdout)
	}
}

// ============================================================================
// CFG-02: collect-all fail-at-load matrix, output-independence, flags parity,
// live-before-bind, log-line leniency, TOML single fail-fast.
// ============================================================================

// liveConfigBody builds a live config with the given [live]/[live.win] body,
// wiring jail/ban paths under dir. globalBody is appended inside [global].
func liveConfigBody(t *testing.T, dir, globalExtra, liveBody string) string {
	t.Helper()
	jailFile := filepath.Join(dir, "jail.json")
	banFile := filepath.Join(dir, "ban.txt")
	body := `
[global]
jailFile = "` + jailFile + `"
banFile = "` + banFile + `"
` + globalExtra + `
[live]
` + liveBody + `
`
	return writeFile(t, dir, "live.toml", body)
}

// assertReportNoAnalysis asserts the run exited 1 with the enumerated header on
// stderr and produced NO analysis output on stdout.
func assertReportNoAnalysis(t *testing.T, stdout, stderr string, code int) {
	t.Helper()
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "configuration errors (") {
		t.Errorf("expected enumerated report header on stderr, got:\n%s", stderr)
	}
	if strings.Contains(stdout, "\"tries\"") || strings.Contains(stdout, "totalRequests") {
		t.Errorf("expected no analysis JSON on stdout, got:\n%s", stdout)
	}
}

// TestCFG02_StaticConfigFailMatrix: each error class in a static --config stops
// at the barrier with exit 1 + the report substring + no analysis.
func TestCFG02_StaticConfigFailMatrix(t *testing.T) {
	cases := []struct {
		name string
		trie string // body of [static.t]
		sub  string
	}{
		{"unknown key", "useForjail = [true]", "useForjail"},
		{"IPv6 cidrRanges", `cidrRanges = ["2001:db8::/48"]`, "IPv6 not supported"},
		{"useForJail mismatch", "clusterArgSets = [[1,0,32,0.1],[2,0,32,0.1]]\nuseForJail = [true]", "useForJail has"},
		{"bad startTime", `startTime = "bad-ts"`, "invalid startTime"},
		{"cluster arity", "clusterArgSets = [[1,0,32]]", "clusterArgSets row 0"},
		{"maxDepth over 32", "clusterArgSets = [[1,0,33,0.1]]", "maxDepth"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := staticConfig(t, dir, tc.trie, "")
			stdout, stderr, code := runFlokbn(t, "static", "--config", cfg)
			assertReportNoAnalysis(t, stdout, stderr, code)
			if !strings.Contains(stderr, tc.sub) {
				t.Errorf("expected %q in report, got:\n%s", tc.sub, stderr)
			}
		})
	}
}

// TestCFG02_StaticBadLogFormat: a [static] logFormat missing %h fails at the
// barrier (load-time logFormat validation).
func TestCFG02_StaticBadLogFormat(t *testing.T) {
	dir := t.TempDir()
	logFile := writeFile(t, dir, "access.log", sampleLogLine)
	body := `
[static]
logFile = "` + logFile + `"
logFormat = "%s %b"

[static.t]
clusterArgSets = [[1, 0, 32, 1.0]]
`
	cfg := writeFile(t, dir, "config.toml", body)
	stdout, stderr, code := runFlokbn(t, "static", "--config", cfg)
	assertReportNoAnalysis(t, stdout, stderr, code)
	if !strings.Contains(stderr, "logFormat") {
		t.Errorf("expected logFormat diagnostic, got:\n%s", stderr)
	}
}

// TestCFG02_StaticUnreadableWhitelist: a configured-but-missing whitelist file
// fails at the barrier (list-file load during Validate).
func TestCFG02_StaticUnreadableWhitelist(t *testing.T) {
	dir := t.TempDir()
	logFile := writeFile(t, dir, "access.log", sampleLogLine)
	missing := filepath.Join(dir, "nope-whitelist.txt")
	body := `
[global]
whitelist = "` + missing + `"

[static]
logFile = "` + logFile + `"

[static.t]
clusterArgSets = [[1, 0, 32, 1.0]]
`
	cfg := writeFile(t, dir, "config.toml", body)
	stdout, stderr, code := runFlokbn(t, "static", "--config", cfg)
	assertReportNoAnalysis(t, stdout, stderr, code)
	if !strings.Contains(stderr, "cannot open") {
		t.Errorf("expected cannot-open diagnostic, got:\n%s", stderr)
	}
}

// TestCFG02_StaticMissingLogfilePlusBadStartTime: a missing logfile AND a bad
// startTime enumerate TOGETHER (proves the logfile stat no longer short-circuits
// before the barrier).
func TestCFG02_StaticMissingLogfilePlusBadStartTime(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope-access.log")
	jailFile := filepath.Join(dir, "jail.json")
	banFile := filepath.Join(dir, "ban.txt")
	body := `
[global]
jailFile = "` + jailFile + `"
banFile = "` + banFile + `"

[static]
logFile = "` + missing + `"

[static.t]
startTime = "bad-ts"
`
	cfg := writeFile(t, dir, "config.toml", body)
	stdout, stderr, code := runFlokbn(t, "static", "--config", cfg)
	assertReportNoAnalysis(t, stdout, stderr, code)
	if !strings.Contains(stderr, "logFile") || !strings.Contains(stderr, "does not exist") {
		t.Errorf("expected logFile-does-not-exist diagnostic, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "invalid startTime") {
		t.Errorf("expected startTime diagnostic enumerated TOGETHER, got:\n%s", stderr)
	}
}

// TestCFG02_StaticOutputIndependence: one bad static config under each output
// dispatch ({default JSON, --compact, --plain, --tui}) exits 1 with the report
// and NO analysis on stdout.
func TestCFG02_StaticOutputIndependence(t *testing.T) {
	for _, mode := range []string{"", "--compact", "--plain", "--tui"} {
		name := mode
		if name == "" {
			name = "default-json"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := staticConfig(t, dir, `startTime = "bad-ts"`, "")
			args := []string{"static", "--config", cfg}
			if mode != "" {
				args = append(args, mode)
			}
			stdout, stderr, code := runFlokbn(t, args...)
			assertReportNoAnalysis(t, stdout, stderr, code)
		})
	}
}

// TestCFG02_LiveBeforeBindMatrix: each live config error class exits 1 with the
// report and NEITHER "starting live loop" NOR "stats server listening" appears
// (no listener bound). statsListen is set so both binds are covered.
func TestCFG02_LiveBeforeBindMatrix(t *testing.T) {
	winOK := `slidingWindowMaxTime = "1m"
slidingWindowMaxSize = 1000
clusterArgSets = [[1, 0, 32, 1.0]]`

	cases := []struct {
		name        string
		globalExtra string
		liveBody    string
		sub         string
	}{
		{
			name:     "missing port",
			liveBody: "statsListen = \"127.0.0.1:0\"\n[live.win]\n" + winOK,
			sub:      "port is required",
		},
		{
			name:     "bad statsListen",
			liveBody: "port = \"5045\"\nstatsListen = \"not-a-hostport-::\"\n[live.win]\n" + winOK,
			sub:      "statsListen",
		},
		{
			name:     "IPv6 cidrRanges in window",
			liveBody: "port = \"5045\"\nstatsListen = \"127.0.0.1:0\"\n[live.win]\n" + winOK + "\ncidrRanges = [\"2001:db8::/48\"]",
			sub:      "IPv6 not supported",
		},
		{
			name:     "useForJail mismatch in window",
			liveBody: "port = \"5045\"\nstatsListen = \"127.0.0.1:0\"\n[live.win]\nslidingWindowMaxTime = \"1m\"\nslidingWindowMaxSize = 1000\nclusterArgSets = [[1,0,32,0.1],[2,0,32,0.1]]\nuseForJail = [true]",
			sub:      "useForJail has",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := liveConfigBody(t, dir, tc.globalExtra, tc.liveBody)
			stdout, stderr, code := runFlokbn(t, "live", "--config", cfg)
			if code != 1 {
				t.Fatalf("expected exit 1, got %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if !strings.Contains(stderr, tc.sub) {
				t.Errorf("expected %q in report, got:\n%s", tc.sub, stderr)
			}
			combined := stdout + stderr
			if strings.Contains(combined, "starting live loop") {
				t.Errorf("ingest bind must NOT happen:\n%s", combined)
			}
			if strings.Contains(combined, "stats server listening") {
				t.Errorf("stats bind must NOT happen:\n%s", combined)
			}
		})
	}
}

// TestCFG02_LiveMissingJailBanFile: a live config missing jailFile/banFile fails
// before bind.
func TestCFG02_LiveMissingJailBanFile(t *testing.T) {
	dir := t.TempDir()
	body := `
[live]
port = "5045"

[live.win]
slidingWindowMaxTime = "1m"
slidingWindowMaxSize = 1000
clusterArgSets = [[1, 0, 32, 1.0]]
`
	cfg := writeFile(t, dir, "live.toml", body)
	stdout, stderr, code := runFlokbn(t, "live", "--config", cfg)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "jailFile is required") || !strings.Contains(stderr, "banFile is required") {
		t.Errorf("expected jailFile+banFile diagnostics, got:\n%s", stderr)
	}
	if strings.Contains(stdout+stderr, "starting live loop") {
		t.Errorf("ingest bind must NOT happen:\n%s", stdout+stderr)
	}
}

// TestCFG02_LiveUnreadableWhitelistBeforeBind: an unreadable whitelist fails
// before the port bind (live strictness increase).
func TestCFG02_LiveUnreadableWhitelistBeforeBind(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope-whitelist.txt")
	cfg := liveConfigBody(t, dir, "whitelist = \""+missing+"\"\n",
		"port = \"5045\"\n[live.win]\nslidingWindowMaxTime = \"1m\"\nslidingWindowMaxSize = 1000\nclusterArgSets = [[1, 0, 32, 1.0]]")
	stdout, stderr, code := runFlokbn(t, "live", "--config", cfg)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "cannot open") {
		t.Errorf("expected cannot-open diagnostic, got:\n%s", stderr)
	}
	if strings.Contains(stdout+stderr, "starting live loop") {
		t.Errorf("ingest bind must NOT happen:\n%s", stdout+stderr)
	}
}

// TestCFG02_LiveBadLogEnumEnumeratesAtBarrier closes the slop2 hole: a bad
// [log] level/format enum in a live --config is a collect-all diagnostic
// (parseLogConfig), but handleLiveConfigMode used to call logging.Setup BEFORE
// the barrier, and logging.Setup hard-fails on a bad enum — so the [log]
// diagnostic AND every other config error were hidden behind a single
// "flokbn:" logging error (violating acceptance #1). The logger install is now
// TOLERANT of a bad config enum, so the enum enumerates at the barrier with the
// rest. Each case asserts (a) the enumerated header appears (NOT the bare
// "flokbn:" path), (b) the [log] enum substring is present, (c) at least one
// OTHER error (missing port/jailFile/banFile) is ALSO present (proves
// collect-all, not fail-fast), and (d) no listener bound.
func TestCFG02_LiveBadLogEnumEnumeratesAtBarrier(t *testing.T) {
	cases := []struct {
		name    string
		logBody string
		enumSub string
	}{
		{"bad level", "level = \"verbose\"", "invalid log level"},
		{"bad format", "format = \"xml\"", "invalid log format"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			// No [global] jailFile/banFile and no [live] port: those required-field
			// diagnostics must ALSO enumerate alongside the [log] enum.
			body := `
[log]
` + tc.logBody + `

[live]

[live.win]
slidingWindowMaxTime = "1m"
slidingWindowMaxSize = 1000
clusterArgSets = [[1, 0, 32, 1.0]]
`
			cfg := writeFile(t, dir, "live.toml", body)
			stdout, stderr, code := runFlokbn(t, "live", "--config", cfg)
			if code != 1 {
				t.Fatalf("expected exit 1, got %d\nstderr:\n%s", code, stderr)
			}
			// The enumerated report header must be present (the barrier fired), NOT
			// just the bare "flokbn:" logging short-circuit.
			if !strings.Contains(stderr, "configuration errors (") {
				t.Fatalf("expected enumerated report header (barrier), got:\n%s", stderr)
			}
			if !strings.Contains(stderr, tc.enumSub) {
				t.Errorf("expected %q in report, got:\n%s", tc.enumSub, stderr)
			}
			// Collect-all: at least one OTHER required-field error must also appear.
			if !strings.Contains(stderr, "port is required") ||
				!strings.Contains(stderr, "jailFile is required") ||
				!strings.Contains(stderr, "banFile is required") {
				t.Errorf("expected the [log] enum to enumerate ALONGSIDE the missing port/jailFile/banFile diagnostics (collect-all), got:\n%s", stderr)
			}
			if strings.Contains(stdout+stderr, "starting live loop") {
				t.Errorf("ingest bind must NOT happen:\n%s", stdout+stderr)
			}
			if strings.Contains(stdout+stderr, "stats server listening") {
				t.Errorf("stats bind must NOT happen:\n%s", stdout+stderr)
			}
		})
	}
}

// TestCFG02_LiveBadLogLevelFlagStaysHard: a bad --logLevel FLAG (a direct CLI
// input, not a config key) stays a TIER-1 hard return via the "flokbn:" path —
// it is NOT migrated to the barrier (no config diagnostic validates a flag), so
// a typo'd flag still fails loud. This guards the asymmetry the slop2 fix keeps:
// the [log] CONFIG enum routes through the barrier; the --logLevel FLAG does not.
func TestCFG02_LiveBadLogLevelFlagStaysHard(t *testing.T) {
	dir := t.TempDir()
	cfg := liveConfigBody(t, dir, "",
		"port = \"5045\"\n[live.win]\nslidingWindowMaxTime = \"1m\"\nslidingWindowMaxSize = 1000\nclusterArgSets = [[1, 0, 32, 1.0]]")
	stdout, stderr, code := runFlokbn(t, "live", "--config", cfg, "--logLevel", "bogus")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "invalid log level") {
		t.Errorf("expected hard logLevel error, got:\n%s", stderr)
	}
	// Tier-1 hard return: the enumerated barrier report must NOT appear for a flag.
	if strings.Contains(stderr, "configuration errors (") {
		t.Errorf("a bad --logLevel FLAG should stay a hard return, not enumerate at the barrier:\n%s", stderr)
	}
	if strings.Contains(stdout+stderr, "starting live loop") {
		t.Errorf("ingest bind must NOT happen:\n%s", stdout+stderr)
	}
}

// TestStaticCommandValidation_BarrierRouted: the static FLAGS cases that now
// route through the barrier (regex / CIDR / missing-logfile), run as a
// SUBPROCESS so the in-process App.Run os.Exit(1) cannot kill the test binary.
func TestStaticCommandValidation_BarrierRouted(t *testing.T) {
	dir := t.TempDir()
	logFile := writeFile(t, dir, "access.log", sampleLogLine)
	missing := filepath.Join(dir, "nope.log")

	cases := []struct {
		name string
		args []string
		sub  string
	}{
		{
			name: "invalid CIDR range",
			args: []string{"static", "--logfile", logFile, "--clusterArgSets", "1000,24,32,0.2", "--rangesCidr", "192.168.1.0/33"},
			sub:  "invalid rangesCidr",
		},
		{
			name: "missing log file",
			args: []string{"static", "--logfile", missing, "--clusterArgSets", "1000,24,32,0.2"},
			sub:  "does not exist",
		},
		{
			name: "invalid user agent regex",
			args: []string{"static", "--logfile", logFile, "--useragentRegex", "[invalid", "--clusterArgSets", "1,1,32,0.1"},
			sub:  "invalid useragentRegex pattern",
		},
		{
			name: "invalid endpoint regex",
			args: []string{"static", "--logfile", logFile, "--endpointRegex", "*invalid", "--clusterArgSets", "1,1,32,0.1"},
			sub:  "invalid endpointRegex pattern",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runFlokbn(t, tc.args...)
			assertReportNoAnalysis(t, stdout, stderr, code)
			if !strings.Contains(stderr, tc.sub) {
				t.Errorf("expected %q in report, got:\n%s", tc.sub, stderr)
			}
		})
	}
}

// TestCFG02_StaticFlagsCollectAll: bad --useragentRegex + a bad --rangesCidr
// enumerate BOTH and analysis NEVER runs (the fail-open assertion: a dropped
// regex diagnostic would silently admit all traffic).
func TestCFG02_StaticFlagsCollectAll(t *testing.T) {
	dir := t.TempDir()
	logFile := writeFile(t, dir, "access.log", sampleLogLine)
	stdout, stderr, code := runFlokbn(t, "static",
		"--logfile", logFile,
		"--useragentRegex", "[invalid",
		"--rangesCidr", "192.168.1.0/33",
		"--clusterArgSets", "1,1,32,0.1")
	assertReportNoAnalysis(t, stdout, stderr, code)
	if !strings.Contains(stderr, "invalid useragentRegex pattern") {
		t.Errorf("expected regex diagnostic, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "invalid rangesCidr") {
		t.Errorf("expected rangesCidr diagnostic enumerated TOGETHER, got:\n%s", stderr)
	}
}

// TestCFG02_LiveFlagsCollectAll: a bad live --useragentRegex enumerates via the
// barrier (live flags parity) before any bind.
func TestCFG02_LiveFlagsCollectAll(t *testing.T) {
	dir := t.TempDir()
	jailFile := filepath.Join(dir, "jail.json")
	banFile := filepath.Join(dir, "ban.txt")
	stdout, stderr, code := runFlokbn(t, "live",
		"--port", "5045",
		"--jailFile", jailFile,
		"--banFile", banFile,
		"--useragentRegex", "[invalid")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "invalid useragentRegex pattern") {
		t.Errorf("expected regex diagnostic, got:\n%s", stderr)
	}
	if strings.Contains(stdout+stderr, "starting live loop") {
		t.Errorf("ingest bind must NOT happen:\n%s", stdout+stderr)
	}
}

// TestCFG02_LogLineLeniency: a VALID config + a log with 1 good + 1 garbage line
// exits 0 (per-record parse errors NEVER feed config diagnostics; the barrier is
// BEFORE log parse).
func TestCFG02_LogLineLeniency(t *testing.T) {
	dir := t.TempDir()
	goodLine := `192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /x HTTP/1.1" 200 1 "-" "UA" "192.168.1.1"`
	garbage := "this is not a valid log line at all"
	logFile := writeFile(t, dir, "access.log", goodLine+"\n"+garbage+"\n")
	jailFile := filepath.Join(dir, "jail.json")
	banFile := filepath.Join(dir, "ban.txt")
	body := `
[global]
jailFile = "` + jailFile + `"
banFile = "` + banFile + `"

[static]
logFile = "` + logFile + `"
logFormat = "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%^\""

[static.t]
clusterArgSets = [[1, 0, 32, 1.0]]
`
	cfg := writeFile(t, dir, "config.toml", body)
	stdout, stderr, code := runFlokbn(t, "static", "--config", cfg)
	if code != 0 {
		t.Fatalf("expected exit 0 (log-line leniency), got %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if strings.Contains(stderr, "configuration errors (") {
		t.Errorf("a garbage LOG LINE must NOT produce a config-errors report:\n%s", stderr)
	}
}

// TestCFG02_TOMLSyntaxSingleFailFast: a broken TOML file is a single hard
// fail-fast via the "flokbn:" path, NOT the enumerated config-errors report.
func TestCFG02_TOMLSyntaxSingleFailFast(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "broken.toml", "[static\nlogFile = \"x\"\n")
	stdout, stderr, code := runFlokbn(t, "static", "--config", cfg)
	if code == 0 {
		t.Fatalf("expected non-zero exit for broken TOML, got 0\nstdout:\n%s", stdout)
	}
	if strings.Contains(stderr, "configuration errors (") {
		t.Errorf("broken TOML must NOT use the enumerated report header:\n%s", stderr)
	}
}
