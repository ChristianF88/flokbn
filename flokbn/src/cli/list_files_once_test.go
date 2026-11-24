//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ChristianF88/flokbn/config"
)

// A static run must open each [global] list file exactly once: the barrier
// reads it and the analysis and the ban publish step work on those entries.
//
// The four list files are FIFOs with exactly one writer each. A second open
// of any of them would block for ever (no writer is left), so the run would
// hit runFlokbn's timeout instead of finishing.
func TestStaticReadsEachListFileOnce(t *testing.T) {
	dir := t.TempDir()
	var log strings.Builder
	for i := 0; i < 200; i++ {
		log.WriteString(strings.ReplaceAll(sampleLogLine, "192.168.1.1", "10.9.8.7"))
	}
	logFile := writeFile(t, dir, "access.log", log.String())
	banFile := filepath.Join(dir, "ban.txt")

	lists := map[string]string{
		"whitelist":          "192.168.0.0/16\n",
		"blacklist":          "203.0.113.0/24\n",
		"userAgentWhitelist": "GoodBot/1.0\n",
		"userAgentBlacklist": "EvilBot/1.0\n",
	}
	global := "jailFile = \"" + filepath.Join(dir, "jail.json") + "\"\nbanFile = \"" + banFile + "\"\n"
	for key, content := range lists {
		fifo := filepath.Join(dir, key)
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Skipf("cannot create a FIFO here: %v", err)
		}
		global += key + " = \"" + fifo + "\"\n"
		// The one writer: its open returns when flokbn opens the FIFO to read.
		go func() {
			w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
			if err != nil {
				return
			}
			_, _ = w.WriteString(content)
			_ = w.Close()
		}()
		// Release a writer flokbn never served, so no goroutine outlives the test.
		t.Cleanup(func() {
			if r, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
				_ = r.Close()
			}
		})
	}
	cfg := writeFile(t, dir, "config.toml", "[global]\n"+global+`
[static]
logFile = "`+logFile+`"

[static.t]
clusterArgSets = [[100, 32, 32, 0.9]]
useForJail = [true]
`)

	_, stderr, code := runFlokbn(t, "static", "--config", cfg, "--compact")
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	ban, err := os.ReadFile(banFile)
	if err != nil {
		t.Fatalf("reading ban file: %v", err)
	}
	// The blacklist entry proves the publish step got the list content, and
	// the detected host that it ran at all.
	for _, want := range []string{"203.0.113.0/24", "10.9.8.7/32"} {
		if !strings.Contains(string(ban), want) {
			t.Errorf("ban file lacks %s:\n%s", want, ban)
		}
	}
}

// Live mode: the barrier reads the list files and newLiveLoop must not read
// them again. With the files removed after Validate a second read would fail.
func TestLiveLoopUsesListsReadAtBarrier(t *testing.T) {
	cfg := newLiveConfigWithUALists(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	}, []string{"192.168.0.0/16"}, []string{"203.0.113.0/24"}, []string{"GoodBot/1.0"}, []string{"EvilBot/1.0"})

	if diags := cfg.Validate(config.LiveMode); diags.HasErrors() {
		t.Fatalf("Validate: %s", diags.Report())
	}
	for _, path := range []string{cfg.Global.Whitelist, cfg.Global.Blacklist, cfg.Global.UserAgentWhitelist, cfg.Global.UserAgentBlacklist} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}

	l, err := newLiveLoop(&fakeIngestor{}, cfg, discardLogger(t), nil)
	if err != nil {
		t.Fatalf("newLiveLoop read a list file again: %v", err)
	}
	if len(l.whitelist) != 1 || l.whitelist[0] != "192.168.0.0/16" {
		t.Errorf("whitelist = %v", l.whitelist)
	}
	if len(l.blacklist) != 1 || l.blacklist[0] != "203.0.113.0/24" {
		t.Errorf("blacklist = %v", l.blacklist)
	}
	if l.uaMatcher == nil || l.uaMatcher.Count() != 2 {
		t.Errorf("User-Agent matcher not built from both lists: %v", l.uaMatcher)
	}
}
