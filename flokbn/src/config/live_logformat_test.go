package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/logparser"
)

// liveConfigTOML returns a valid live config with the given extra lines in
// [global], [live] and the one window [live.w].
func liveConfigTOML(t *testing.T, global, live, window string) string {
	t.Helper()
	dir := t.TempDir()
	return fmt.Sprintf(`
[global]
jailFile = %q
banFile = %q
%s
[live]
port = "9000"
%s
[live.w]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 10
clusterArgSets = [[100, 24, 32, 0.1]]
%s
`, filepath.Join(dir, "jail.json"), filepath.Join(dir, "ban.txt"), global, live, window)
}

// Live mode has its own logFormat with its own default: the client IP in the
// first field, as live mode always read it - not the static default, which
// reads a trailing field.
func TestLiveLogFormat_KeyAndDefault(t *testing.T) {
	cfg, err := loadConfigString(t, liveConfigTOML(t, "", "", ""))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.GetLiveLogFormat(); got != logparser.DefaultLiveLogFormat {
		t.Errorf("GetLiveLogFormat() = %q, want the live default %q", got, logparser.DefaultLiveLogFormat)
	}
	if logparser.DefaultLiveLogFormat == logparser.DefaultLogFormat {
		t.Error("live and static defaults are the same; live must default to the IP-first layout")
	}
	if !strings.HasPrefix(logparser.DefaultLiveLogFormat, "%h ") {
		t.Errorf("live default %q does not read the client IP from the first field", logparser.DefaultLiveLogFormat)
	}
	if d := cfg.Validate(LiveMode); d.HasErrors() {
		t.Fatalf("default live config rejected:\n%s", d.Report())
	}

	const custom = `%^ %^ %^ [%t] "%r" %s %b "%^" "%u" "%h"`
	cfg, err = loadConfigString(t, liveConfigTOML(t, "", fmt.Sprintf("logFormat = %q", custom), ""))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.GetLiveLogFormat(); got != custom {
		t.Errorf("GetLiveLogFormat() = %q, want %q", got, custom)
	}
	if d := cfg.Validate(LiveMode); d.HasErrors() {
		t.Fatalf("custom live logFormat rejected:\n%s", d.Report())
	}

	// A [static] logFormat does not leak into live mode.
	cfg, err = loadConfigString(t, liveConfigTOML(t, "", "", "")+"\n[static]\nlogFormat = \"%h\"\n")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.GetLiveLogFormat(); got != logparser.DefaultLiveLogFormat {
		t.Errorf("[static] logFormat changed the live format to %q", got)
	}

	// Flags mode builds the Config by hand; a nil section must not panic.
	if got := (&Config{}).GetLiveLogFormat(); got != logparser.DefaultLiveLogFormat {
		t.Errorf("GetLiveLogFormat() on an empty Config = %q", got)
	}

	if _, err := loadConfigString(t, liveConfigTOML(t, "", "logFormat = 5", "")); err == nil ||
		!strings.Contains(err.Error(), "logFormat must be a string") {
		t.Errorf("non-string logFormat: err = %v, want 'logFormat must be a string'", err)
	}
}

// [live] logFormat goes through the same ValidateFormat as [static] logFormat,
// must carry a timestamp, and is cross-checked against the filters that read
// request fields - the live counterpart of the static check (C2).
func TestLiveLogFormat_Validation(t *testing.T) {
	uaList := filepath.Join(t.TempDir(), "ua.txt")
	if err := os.WriteFile(uaList, []byte("GoodBot/1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		logFormat string
		global    string
		window    string
		want      [][]string // per expected diagnostic: substrings of one line; nil = none
	}{
		{
			name:      "no %h",
			logFormat: `[%t] "%r"`,
			want:      [][]string{{"[live] invalid logFormat", "exactly one %h"}},
		},
		{
			name:      "duplicate field",
			logFormat: `%h %h [%t]`,
			want:      [][]string{{"[live] invalid logFormat", "duplicate"}},
		},
		{
			name:      "unsupported code",
			logFormat: `%h [%t] %q`,
			want:      [][]string{{"[live] invalid logFormat", "unsupported format code"}},
		},
		{
			name:      "invalid format is reported once, without follow-up filter diagnostics",
			logFormat: `[%t] "%r"`,
			window:    `useragentRegex = "bot"`,
			want:      [][]string{{"[live] invalid logFormat"}},
		},
		{
			name:      "no %t",
			logFormat: `%h "%r" %s %b "%u"`,
			want:      [][]string{{"[live] logFormat", "no %t field", "sliding windows"}},
		},
		{
			name:      "useragentRegex without %u",
			logFormat: `%h %^ %^ [%t] "%r" %s %b`,
			window:    `useragentRegex = "bot"`,
			want:      [][]string{{"[live.w] useragentRegex", "[live] logFormat", "%u"}},
		},
		{
			name:      "endpointRegex without %r or %U",
			logFormat: `%h %^ %^ [%t] %s %b "%u"`,
			window:    `endpointRegex = "^/api/"`,
			want:      [][]string{{"[live.w] endpointRegex", "[live] logFormat", "%r or %U"}},
		},
		{
			name:      "endpointRegex with %U",
			logFormat: `%h [%t] %m %U %s`,
			window:    `endpointRegex = "^/api/"`,
		},
		{
			name:      "userAgentWhitelist without %u",
			logFormat: `%h %^ %^ [%t] "%r" %s %b`,
			global:    fmt.Sprintf("userAgentWhitelist = %q", uaList),
			want:      [][]string{{"[global] userAgentWhitelist", "[live] logFormat", "%u"}},
		},
		{
			name:      "userAgentBlacklist without %u",
			logFormat: `%h %^ %^ [%t] "%r" %s %b`,
			global:    fmt.Sprintf("userAgentBlacklist = %q", uaList),
			want:      [][]string{{"[global] userAgentBlacklist", "[live] logFormat", "%u"}},
		},
		{
			name:      "every unmet requirement is reported",
			logFormat: `%h`,
			global:    fmt.Sprintf("userAgentWhitelist = %q", uaList),
			window:    "useragentRegex = \"bot\"\nendpointRegex = \"^/x\"",
			want: [][]string{
				{"no %t field"},
				{"[live.w] useragentRegex"},
				{"[live.w] endpointRegex"},
				{"[global] userAgentWhitelist"},
			},
		},
		{
			name:      "filters with the fields they need",
			logFormat: `%^ %^ %^ [%t] "%r" %s %b "%^" "%u" "%h"`,
			global:    fmt.Sprintf("userAgentWhitelist = %q", uaList),
			window:    "useragentRegex = \"bot\"\nendpointRegex = \"^/x\"",
		},
		{
			name:   "default format serves every filter",
			global: fmt.Sprintf("userAgentBlacklist = %q", uaList),
			window: "useragentRegex = \"bot\"\nendpointRegex = \"^/x\"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			live := ""
			if tt.logFormat != "" {
				live = fmt.Sprintf("logFormat = %q", tt.logFormat)
			}
			cfg, err := loadConfigString(t, liveConfigTOML(t, tt.global, live, tt.window))
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			d := cfg.Validate(LiveMode)
			if d.Len() != len(tt.want) {
				t.Fatalf("want %d diagnostics, got %d:\n%s", len(tt.want), d.Len(), d.Report())
			}
			for _, wantLine := range tt.want {
				found := false
				for _, line := range d.msgs {
					all := true
					for _, sub := range wantLine {
						all = all && strings.Contains(line, sub)
					}
					found = found || all
				}
				if !found {
					t.Errorf("no diagnostic line contains all of %q, got:\n%s", wantLine, d.Report())
				}
			}
			// The static check is a separate one: this config has no [static]
			// section and must not trip it.
			for _, line := range d.msgs {
				if strings.Contains(line, "[static") {
					t.Errorf("live validation produced a static diagnostic: %s", line)
				}
			}
		})
	}
}
