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
