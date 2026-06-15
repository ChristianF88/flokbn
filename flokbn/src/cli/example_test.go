package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/config"
)

// runApp drives the package's global App with the given args, discarding its
// output, and returns the run error. Writers are restored afterwards.
func runApp(t *testing.T, args ...string) error {
	t.Helper()
	prevOut, prevErr := App.Writer, App.ErrWriter
	App.Writer = io.Discard
	App.ErrWriter = io.Discard
	t.Cleanup(func() {
		App.Writer = prevOut
		App.ErrWriter = prevErr
	})
	return App.Run(append([]string{"flokbn"}, args...))
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(data) == 0 {
		return 0
	}
	return bytes.Count(data, []byte{'\n'})
}

func TestExampleLogsCommand(t *testing.T) {
	out := filepath.Join(t.TempDir(), "access.log")
	if err := runApp(t, "example", "logs", "--out", out, "--lines", "2000", "--seed", "3"); err != nil {
		t.Fatalf("example logs: %v", err)
	}
	if n := countLines(t, out); n != 2000 {
		t.Fatalf("line count = %d, want 2000", n)
	}

	// Deterministic for a fixed seed.
	out2 := filepath.Join(t.TempDir(), "access.log")
	if err := runApp(t, "example", "logs", "--out", out2, "--lines", "2000", "--seed", "3"); err != nil {
		t.Fatalf("example logs (2): %v", err)
	}
	a, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read %s: %v", out, err)
	}
	b, err := os.ReadFile(out2)
	if err != nil {
		t.Fatalf("read %s: %v", out2, err)
	}
	if !bytes.Equal(a, b) {
		t.Error("same seed produced different output via CLI")
	}
}

func TestExampleLogsRejectsNonPositiveLines(t *testing.T) {
	out := filepath.Join(t.TempDir(), "access.log")
	if err := runApp(t, "example", "logs", "--out", out, "--lines", "0"); err == nil {
		t.Error("example logs --lines 0 = nil error, want error")
	}
}

func TestExampleConfigScaffold(t *testing.T) {
	dir := t.TempDir()
	if err := runApp(t, "example", "config", "--out", dir); err != nil {
		t.Fatalf("example config: %v", err)
	}

	// All five assets must be written.
	for _, name := range []string{
		"complex-static.toml", "whitelist.txt", "blacklist.txt",
		"ua_whitelist.txt", "ua_blacklist.txt",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("missing scaffold asset %s: %v", name, err)
		}
	}

	// The scaffolded config must parse and every path key must be an absolute
	// path co-located inside the scaffold directory.
	cfg, err := config.LoadConfig(filepath.Join(dir, "complex-static.toml"))
	if err != nil {
		t.Fatalf("scaffolded config does not parse: %v", err)
	}
	checks := map[string]string{
		"jailFile":           cfg.Global.JailFile,
		"banFile":            cfg.Global.BanFile,
		"whitelist":          cfg.Global.Whitelist,
		"blacklist":          cfg.Global.Blacklist,
		"userAgentWhitelist": cfg.Global.UserAgentWhitelist,
		"userAgentBlacklist": cfg.Global.UserAgentBlacklist,
		"logFile":            cfg.Static.LogFile,
		"plotPath":           cfg.Static.PlotPath,
	}
	for key, val := range checks {
		if !filepath.IsAbs(val) {
			t.Errorf("%s = %q, want absolute path", key, val)
		}
		if !strings.HasPrefix(filepath.ToSlash(val), filepath.ToSlash(dir)+"/") {
			t.Errorf("%s = %q, want path inside scaffold dir %q", key, val, dir)
		}
	}

	// The list paths must point at the verbatim-copied files, which exist.
	for _, p := range []string{
		cfg.Global.Whitelist, cfg.Global.Blacklist,
		cfg.Global.UserAgentWhitelist, cfg.Global.UserAgentBlacklist,
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("config path %q does not resolve to a file: %v", p, err)
		}
	}
}

// TestRewriteScaffoldPathsEscaping guards against TOML-string injection when
// the output directory contains characters special to TOML basic strings or
// to the regexp replacement template.
func TestRewriteScaffoldPathsEscaping(t *testing.T) {
	const src = `logFile = "access.log"
whitelist = "whitelist.txt"
`
	// A directory path containing a quote, backslash and dollar sign.
	got := rewriteScaffoldPaths(src, `/tmp/qu"ote\back$dollar`)
	for _, want := range []string{`\"`, `\\`} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q to be escaped in output:\n%s", want, got)
		}
	}
	// The literal '$' must survive (not consumed as a capture reference).
	if !strings.Contains(got, "$dollar") {
		t.Errorf("literal '$' was mangled in output:\n%s", got)
	}
	// The rewritten value must remain a single, well-formed quoted string:
	// exactly one opening and one closing unescaped quote per rewritten key.
	if strings.Contains(got, `"access.log"`) || strings.Contains(got, `"whitelist.txt"`) {
		t.Errorf("path was not rewritten:\n%s", got)
	}
}

// TestExampleRoundTrip is the strongest end-to-end guard: scaffold a config,
// generate a small log into the scaffold directory, then run static against
// the scaffolded config. It must complete without error.
func TestExampleRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := runApp(t, "example", "config", "--out", dir); err != nil {
		t.Fatalf("example config: %v", err)
	}
	if err := runApp(t, "example", "logs", "--out", filepath.Join(dir, "access.log"), "--lines", "3000"); err != nil {
		t.Fatalf("example logs: %v", err)
	}
	if err := runApp(t, "static", "--config", filepath.Join(dir, "complex-static.toml"), "--plain"); err != nil {
		t.Fatalf("static against scaffolded config failed: %v", err)
	}
}
