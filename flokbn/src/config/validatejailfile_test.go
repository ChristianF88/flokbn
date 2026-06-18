package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests pin the pre-work-barrier wiring for the jail file: Validate must
// surface an unloadable (zero-cell/corrupt) jail as a diagnostic so the barrier
// aborts before any analysis or ban-file write — instead of the static path
// silently swallowing it and exiting 0 with no bans. The FileToJail unit tests
// (jail/io_test.go) cover the loader itself; these cover that Validate is wired
// to it, which is where the silent-swallow regression lived.

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

const jailTestLogLine = "1.2.3.4 - - [01/Feb/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"x\"\n"

// Static mode validates the jail only when it will be loaded (jailFile AND
// banFile set); a zero-cell jail must then produce the diagnostic.
func TestValidateJailFile_StaticZeroCellFailsLoud(t *testing.T) {
	dir := t.TempDir()
	jailFile := filepath.Join(dir, "jail.json")
	logFile := filepath.Join(dir, "access.log")
	writeFile(t, jailFile, "{}")
	writeFile(t, logFile, jailTestLogLine)
	content := fmt.Sprintf(`
[global]
jailFile = %q
banFile = %q
[static]
logFile = %q
[static.t]
clusterArgSets = [[10, 8, 32, 0.5]]
useForJail = [true]
`, jailFile, filepath.Join(dir, "ban.txt"), logFile)

	cfg, err := loadConfigString(t, content)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	report := cfg.Validate(StaticMode).Report()
	if !strings.Contains(report, "parsed to zero cells") {
		t.Fatalf("expected a zero-cell jail diagnostic, got:\n%s", report)
	}
}

// A missing jail file is the canonical fresh start (FileToJail returns a new
// jail), so it must NOT produce any diagnostic.
func TestValidateJailFile_StaticMissingIsFresh(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "access.log")
	writeFile(t, logFile, jailTestLogLine)
	content := fmt.Sprintf(`
[global]
jailFile = %q
banFile = %q
[static]
logFile = %q
[static.t]
clusterArgSets = [[10, 8, 32, 0.5]]
useForJail = [true]
`, filepath.Join(dir, "jail.json"), filepath.Join(dir, "ban.txt"), logFile)

	cfg, err := loadConfigString(t, content)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if d := cfg.Validate(StaticMode); d.HasErrors() {
		t.Fatalf("missing jail file should be a fresh start (no diagnostics), got:\n%s", d.Report())
	}
}

// Live mode loads the jail unconditionally, so a zero-cell jail must be caught
// even with no banFile configured.
func TestValidateJailFile_LiveZeroCellFailsLoud(t *testing.T) {
	dir := t.TempDir()
	jailFile := filepath.Join(dir, "jail.json")
	writeFile(t, jailFile, "null")
	content := fmt.Sprintf(`
[global]
jailFile = %q
banFile = %q
[live]
port = "5044"
[live.w]
slidingWindowMaxTime = "5m"
slidingWindowMaxSize = 1000
clusterArgSets = [[10, 8, 32, 0.5]]
useForJail = [true]
`, jailFile, filepath.Join(dir, "ban.txt"))

	cfg, err := loadConfigString(t, content)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	report := cfg.Validate(LiveMode).Report()
	if !strings.Contains(report, "parsed to zero cells") {
		t.Fatalf("live mode must validate the jail; got:\n%s", report)
	}
}
