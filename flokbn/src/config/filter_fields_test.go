package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// C2: a filter that reads a request field the logFormat never extracts used to
// silently match nothing (regex / UA lists / startTime) or everything
// (endTime). Validate(StaticMode) must reject the combination instead.
func TestValidate_FilterNeedsFieldMissingFromLogFormat(t *testing.T) {
	dir := t.TempDir()
	uaList := filepath.Join(dir, "ua.txt")
	if err := os.WriteFile(uaList, []byte("GoodBot/1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		logFormat string
		global    string
		trie      string
		want      []string // substrings that must all appear in one report ("" list = no diagnostics)
	}{
		{
			name:      "useragentRegex without %u",
			logFormat: `%h %^ %^ [%t] "%r" %s %b`,
			trie:      `useragentRegex = "bot"`,
			want:      []string{"[static.t] useragentRegex", "%u"},
		},
		{
			name:      "endpointRegex without %r or %U",
			logFormat: `%h %^ %^ [%t] %s %b "%u"`,
			trie:      `endpointRegex = "^/api/"`,
			want:      []string{"[static.t] endpointRegex", "%r or %U"},
		},
		{
			name:      "startTime without %t",
			logFormat: `%h "%r" %s %b "%u"`,
			trie:      `startTime = "2025-01-01T00:00:00Z"`,
			want:      []string{"[static.t] startTime", "%t"},
		},
		{
			name:      "endTime without %t",
			logFormat: `%h "%r" %s %b "%u"`,
			trie:      `endTime = "2025-01-01T00:00:00Z"`,
			want:      []string{"[static.t] endTime", "%t"},
		},
		{
			name:      "userAgentWhitelist without %u",
			logFormat: `%h %^ %^ [%t] "%r" %s %b`,
			global:    fmt.Sprintf("userAgentWhitelist = %q", uaList),
			want:      []string{"[global] userAgentWhitelist", "%u"},
		},
		{
			name:      "userAgentBlacklist without %u",
			logFormat: `%h %^ %^ [%t] "%r" %s %b`,
			global:    fmt.Sprintf("userAgentBlacklist = %q", uaList),
			want:      []string{"[global] userAgentBlacklist", "%u"},
		},
		{
			name:      "endpointRegex with %r",
			logFormat: `%h "%r"`,
			trie:      `endpointRegex = "^/api/"`,
		},
		{
			name:      "endpointRegex with %U",
			logFormat: `%h %m %U`,
			trie:      `endpointRegex = "^/api/"`,
		},
		{
			name:      "all filters with all fields",
			logFormat: `%h [%t] "%r" "%u"`,
			global:    fmt.Sprintf("userAgentWhitelist = %q\nuserAgentBlacklist = %q", uaList, uaList),
			trie:      "useragentRegex = \"bot\"\nendpointRegex = \"^/api/\"\nstartTime = \"2025-01-01T00:00:00Z\"\nendTime = \"2025-01-02T00:00:00Z\"",
		},
		{
			name: "default format carries every field",
			trie: "useragentRegex = \"bot\"\nendpointRegex = \"^/api/\"\nstartTime = \"2025-01-01T00:00:00Z\"",
		},
		{
			name:      "no filters, IP-only format",
			logFormat: `%h`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b strings.Builder
			fmt.Fprintf(&b, "[global]\n%s\n[static]\n", tt.global)
			if tt.logFormat != "" {
				fmt.Fprintf(&b, "logFormat = %q\n", tt.logFormat)
			}
			fmt.Fprintf(&b, "[static.t]\nclusterArgSets = [[100, 24, 32, 0.1]]\n%s\n", tt.trie)

			cfg, err := loadConfigString(t, b.String())
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			d := cfg.Validate(StaticMode)
			if len(tt.want) == 0 {
				if d.HasErrors() {
					t.Fatalf("want no diagnostics, got:\n%s", d.Report())
				}
				return
			}
			if d.Len() != 1 {
				t.Fatalf("want exactly 1 diagnostic, got %d:\n%s", d.Len(), d.Report())
			}
			for _, want := range tt.want {
				if !strings.Contains(d.Report(), want) {
					t.Errorf("report should contain %q, got:\n%s", want, d.Report())
				}
			}
		})
	}
}

// Every unmet requirement is reported in one pass (collect-all), and the check
// does not pile on top of an invalid logFormat (which is its own diagnostic).
func TestValidate_FilterFieldRequirementsCollectAll(t *testing.T) {
	cfg, err := loadConfigString(t, `
[static]
logFormat = "%h"
[static.a]
useragentRegex = "bot"
endpointRegex = "^/x"
[static.b]
startTime = "2025-01-01T00:00:00Z"
endTime = "2025-01-02T00:00:00Z"
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	d := cfg.Validate(StaticMode)
	if d.Len() != 4 {
		t.Fatalf("want 4 diagnostics, got %d:\n%s", d.Len(), d.Report())
	}

	cfg, err = loadConfigString(t, `
[static]
logFormat = "%^ no ip field"
[static.a]
useragentRegex = "bot"
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	d = cfg.Validate(StaticMode)
	if d.Len() != 1 || !strings.Contains(d.Report(), "invalid logFormat") {
		t.Fatalf("want only the logFormat diagnostic, got %d:\n%s", d.Len(), d.Report())
	}
}

// Live mode ignores [static] logFormat, so the cross-check must not fire there.
func TestValidate_FilterFieldRequirementsStaticOnly(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfigString(t, fmt.Sprintf(`
[global]
jailFile = %q
banFile = %q
[static]
logFormat = "%%h"
[live]
port = "9000"
[live.w]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 10
clusterArgSets = [[100, 24, 32, 0.1]]
useragentRegex = "bot"
endpointRegex = "^/x"
`, filepath.Join(dir, "jail.json"), filepath.Join(dir, "ban.txt")))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if d := cfg.Validate(LiveMode); d.HasErrors() {
		t.Fatalf("live mode must not cross-check [static] logFormat, got:\n%s", d.Report())
	}
}

// The shipped example configs must keep loading: the only diagnostics allowed
// are the missing-file ones caused by their relative/illustrative paths.
func TestShippedExamplesStillValidate(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	examples := []string{
		filepath.Join(root, "flokbn.toml.example"),
		filepath.Join(root, "config_examples", "complex-static.toml"),
	}
	fileProblem := func(line string) bool {
		return strings.Contains(line, "does not exist") ||
			strings.Contains(line, "cannot open") ||
			strings.Contains(line, "no such file or directory")
	}
	for _, path := range examples {
		t.Run(filepath.Base(path), func(t *testing.T) {
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatalf("LoadConfig(%s): %v", path, err)
			}
			modes := map[string]RunMode{"static": StaticMode}
			if len(cfg.LiveTries) > 0 {
				modes["live"] = LiveMode
			}
			for modeName, mode := range modes {
				for _, line := range cfg.Validate(mode).msgs {
					if !fileProblem(line) {
						t.Errorf("%s mode: shipped example rejected: %s", modeName, line)
					}
				}
			}
		})
	}
}
