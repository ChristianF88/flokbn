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

func TestStaticDemoScaffold(t *testing.T) {
	dir := t.TempDir()
	if err := runApp(t, "generate", "static-demo", "--out", dir); err != nil {
		t.Fatalf("generate static-demo: %v", err)
	}

	// All six artifacts must be written: config, log, and the four list files.
	for _, name := range []string{
		"complex-static.toml", "access.log", "whitelist.txt", "blacklist.txt",
		"ua_whitelist.txt", "ua_blacklist.txt",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("missing demo artifact %s: %v", name, err)
		}
	}

	// The demo always writes the fixed 1,000,000-line log.
	if n := countLines(t, filepath.Join(dir, "access.log")); n != 1_000_000 {
		t.Errorf("access.log line count = %d, want 1000000", n)
	}

	// The config must parse and every path key must be an absolute path
	// co-located inside the demo directory.
	cfg, err := config.LoadConfig(filepath.Join(dir, "complex-static.toml"))
	if err != nil {
		t.Fatalf("generated config does not parse: %v", err)
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
			t.Errorf("%s = %q, want path inside demo dir %q", key, val, dir)
		}
	}
}

// TestStaticDemoRefusesAndWritesNothing verifies the refuse-up-front contract:
// if any target name already exists in --out, the command aborts BEFORE writing
// anything, so no scaffold artifact is created and pre-existing user data is
// untouched. Here a DIRECTORY occupies the config path (complex-static.toml);
// the up-front stat detects it and the command refuses before writing any list
// file, rather than overwriting the list files and then deleting them.
func TestStaticDemoRefusesAndWritesNothing(t *testing.T) {
	dir := t.TempDir()

	// Pre-existing, unrelated user data that must survive.
	keep := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(keep, []byte("precious"), 0o644); err != nil {
		t.Fatalf("seed keep.txt: %v", err)
	}

	// A directory occupying a target path is itself a pre-existing target: the
	// up-front stat returns nil (the path exists), so the command must refuse.
	if err := os.Mkdir(filepath.Join(dir, demoConfigName), 0o755); err != nil {
		t.Fatalf("seed blocking directory: %v", err)
	}

	err := runApp(t, "generate", "static-demo", "--out", dir)
	if err == nil {
		t.Fatal("generate static-demo into dir with pre-existing target = nil error, want error")
	}

	// The refusal happens before any write, so none of the list files were ever
	// created.
	for _, name := range demoLists {
		if _, statErr := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(statErr) {
			t.Errorf("list file %s must NOT be written when the command refuses up-front (stat err: %v)", name, statErr)
		}
	}
	// The synthetic log must not have been created either.
	if _, statErr := os.Stat(filepath.Join(dir, "access.log")); !os.IsNotExist(statErr) {
		t.Errorf("access.log must NOT be written when the command refuses up-front (stat err: %v)", statErr)
	}

	// Pre-existing data must be untouched.
	data, readErr := os.ReadFile(keep)
	if readErr != nil {
		t.Fatalf("pre-existing keep.txt was removed or corrupted: %v", readErr)
	}
	if string(data) != "precious" {
		t.Errorf("keep.txt contents = %q, want %q", data, "precious")
	}
}

// TestStaticDemoRefusesToOverwriteExistingFile is the URGENT-20 regression: a
// pre-existing REGULAR file at a target name (whitelist.txt) holding user data
// must survive byte-for-byte. The pre-fix code overwrote it and, on any later
// failure, deleted it; the fix stat-refuses all targets up-front, so the file
// is never touched and nothing else is written.
func TestStaticDemoRefusesToOverwriteExistingFile(t *testing.T) {
	dir := t.TempDir()

	const userData = "USER DATA\n"
	target := filepath.Join(dir, "whitelist.txt")
	if err := os.WriteFile(target, []byte(userData), 0o644); err != nil {
		t.Fatalf("seed whitelist.txt: %v", err)
	}

	// Unrelated user data that must also survive.
	keep := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(keep, []byte("precious"), 0o644); err != nil {
		t.Fatalf("seed keep.txt: %v", err)
	}

	err := runApp(t, "generate", "static-demo", "--out", dir)
	if err == nil {
		t.Fatal("generate static-demo over pre-existing whitelist.txt = nil error, want error")
	}
	if !strings.Contains(err.Error(), "overwrite") || !strings.Contains(err.Error(), "whitelist.txt") {
		t.Errorf("error %q should mention refusing to overwrite whitelist.txt", err)
	}

	// The core of the PoC: the pre-existing file survives with original contents.
	got, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("pre-existing whitelist.txt was removed or corrupted: %v", readErr)
	}
	if string(got) != userData {
		t.Errorf("whitelist.txt contents = %q, want original %q", got, userData)
	}

	// Refusing up-front means no other scaffold artifact was left behind.
	for _, name := range []string{
		"blacklist.txt", "ua_whitelist.txt", "ua_blacklist.txt",
		demoConfigName, "access.log",
	} {
		if _, statErr := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(statErr) {
			t.Errorf("artifact %s must NOT be written when the command refuses (stat err: %v)", name, statErr)
		}
	}

	// Unrelated data must be untouched.
	data, readErr := os.ReadFile(keep)
	if readErr != nil {
		t.Fatalf("pre-existing keep.txt was removed or corrupted: %v", readErr)
	}
	if string(data) != "precious" {
		t.Errorf("keep.txt contents = %q, want %q", data, "precious")
	}
}

// TestDirsToCreate guards the nested-output-dir cleanup contract: dirsToCreate
// must report exactly the directories os.MkdirAll(absDir) would create, deepest
// first (leaf before parent), and nothing that already exists. The failure-path
// cleanup in handleStaticDemo os.Removes these in order, so an off-by-one here
// would either leak an empty intermediate directory the command created or
// attempt to remove a pre-existing ancestor it must not touch.
func TestDirsToCreate(t *testing.T) {
	base := t.TempDir() // exists; must never appear in the result

	// base/a/b/leaf — a, b and leaf do not exist yet.
	leaf := filepath.Join(base, "a", "b", "leaf")
	got := dirsToCreate(leaf)
	want := []string{
		leaf,
		filepath.Join(base, "a", "b"),
		filepath.Join(base, "a"),
	}
	if len(got) != len(want) {
		t.Fatalf("dirsToCreate(%q) = %v, want %v", leaf, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dirsToCreate[%d] = %q, want %q (must be deepest-first)", i, got[i], want[i])
		}
	}

	// An already-existing directory means we create nothing.
	if got := dirsToCreate(base); len(got) != 0 {
		t.Errorf("dirsToCreate(existing dir) = %v, want empty", got)
	}

	// A partially existing chain: only the missing tail is ours.
	mid := filepath.Join(base, "x")
	if err := os.Mkdir(mid, 0o755); err != nil {
		t.Fatalf("seed mid dir: %v", err)
	}
	leaf2 := filepath.Join(mid, "y", "z")
	got2 := dirsToCreate(leaf2)
	want2 := []string{leaf2, filepath.Join(mid, "y")}
	if len(got2) != len(want2) {
		t.Fatalf("dirsToCreate(%q) = %v, want %v (existing %q must be excluded)", leaf2, got2, want2, mid)
	}
	for i := range want2 {
		if got2[i] != want2[i] {
			t.Errorf("dirsToCreate[%d] = %q, want %q", i, got2[i], want2[i])
		}
	}
}

// TestStaticDemoDetectsClusters is the strongest end-to-end guard: the demo,
// when analyzed with its own config, must actually detect threat ranges. This
// is what guarantees the fixed 1,000,000-line log and its calibrated config
// stay in sync — a calibration regression would surface as an empty report. It
// runs the REAL command (full 1M log) end-to-end on purpose.
func TestStaticDemoDetectsClusters(t *testing.T) {
	dir := t.TempDir()
	if err := runApp(t, "generate", "static-demo", "--out", dir); err != nil {
		t.Fatalf("generate static-demo: %v", err)
	}

	cfgPath := filepath.Join(dir, "complex-static.toml")

	// The plain report is written to os.Stdout, so capture that stream (the
	// App.Writer is not used by outputPlain). runAppCaptured handles the swap.
	out, err := runAppCaptured(t, []string{"flokbn", "static", "--config", cfgPath, "--plain"})
	if err != nil {
		t.Fatalf("static against generated demo failed: %v", err)
	}

	if !strings.Contains(out, "Detected Threat Ranges") {
		t.Errorf("generated demo detected no threat ranges at its calibrated size; "+
			"log and config are out of sync.\n--- output ---\n%s", out)
	}
}

// TestScaffoldRewriteContract guards the embedded-config path-rewrite contract.
// rewriteScaffoldPaths is a set of line-anchored regexes against the committed
// exampledata/complex-static.toml. If that TOML is ever reformatted in a way the
// regexes no longer match — a renamed key, a reflowed line, indentation the
// anchor rejects — the rewrites would silently no-op and `generate static-demo`
// would emit a config with relative dangling paths, with no error. This test
// reads the embedded asset exactly as handleStaticDemo does, runs the same
// rewrite, and asserts every contract point still fires, so such a reformat
// fails loudly.
func TestScaffoldRewriteContract(t *testing.T) {
	raw, err := demoAssets.ReadFile("exampledata/" + demoConfigName)
	if err != nil {
		t.Fatalf("read embedded %s: %v", demoConfigName, err)
	}
	rawStr := string(raw)

	absDir := t.TempDir()
	out := rewriteScaffoldPaths(rawStr, absDir)

	// Every demoPaths key must have been rewritten to an absolute, co-located
	// path. Find each key's line in the output and require it to contain absDir;
	// count the keys that did, and require all of them.
	slashDir := filepath.ToSlash(absDir)
	rewritten := 0
	for _, p := range demoPaths {
		var keyLine string
		for _, line := range strings.Split(out, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, p.key+" ") || strings.HasPrefix(trimmed, p.key+"=") {
				keyLine = line
				break
			}
		}
		if keyLine == "" {
			t.Errorf("path key %q not found in rewritten config (key renamed or line reflowed?)", p.key)
			continue
		}
		// The value must point inside the demo dir at the co-located file. A
		// silent no-op leaves the original relative value, which lacks absDir.
		want := filepath.ToSlash(filepath.Join(absDir, p.file))
		if !strings.Contains(keyLine, want) {
			t.Errorf("path key %q was not rewritten to its co-located absolute path:\n  line:  %s\n  want substring: %s", p.key, keyLine, want)
			continue
		}
		if !strings.Contains(keyLine, slashDir) {
			t.Errorf("path key %q line does not contain demo dir %q: %s", p.key, slashDir, keyLine)
			continue
		}
		rewritten++
	}
	if rewritten != len(demoPaths) {
		t.Errorf("rewriteScaffoldPaths rewrote %d of %d path keys; the regex contract is broken", rewritten, len(demoPaths))
	}
}
