package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/logparser"
)

// TestOversizedLineIsSkippedAndReported: a line longer than
// logparser.MaxLineLen no longer aborts a static run ("token too long"). It is
// skipped, the remaining lines are analysed, and an `oversized_lines` warning
// says how many were dropped - on the IP-only path and on the full-parse path.
func TestOversizedLineIsSkippedAndReported(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	huge := `192.168.1.9 - - [01/Jan/2025:00:00:02 +0000] "GET /` + strings.Repeat("a", logparser.MaxLineLen) + ` HTTP/1.1" 200 100 "-" "Mozilla/5.0" "192.168.1.9"`
	logContent := `192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET /a HTTP/1.1" 200 100 "-" "Mozilla/5.0" "192.168.1.1"
` + huge + `

192.168.1.2 - - [01/Jan/2025:00:00:04 +0000] "GET /e HTTP/1.1" 200 100 "-" "Mozilla/5.0" "192.168.1.2"
`
	if err := os.WriteFile(logFile, []byte(logContent), 0644); err != nil {
		t.Fatalf("Failed to create log file: %v", err)
	}
	jailFile := filepath.Join(tmpDir, "jail.json")
	banFile := filepath.Join(tmpDir, "ban.txt")
	if err := os.WriteFile(banFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create ban file: %v", err)
	}

	for name, withTimeFilter := range map[string]bool{"IP-only path": false, "full-parse path": true} {
		t.Run(name, func(t *testing.T) {
			cfg := loadMalformedFieldConfig(t, logFile, jailFile, banFile, withTimeFilter)
			result, err := Static(cfg)
			if err != nil {
				t.Fatalf("Static failed on a log with an oversized line: %v", err)
			}
			// Two real requests: the oversized line and the blank line are not requests.
			if result.General.TotalRequests != 2 {
				t.Errorf("TotalRequests = %d, want 2", result.General.TotalRequests)
			}
			found := false
			for _, w := range result.Warnings {
				if w.Type != "oversized_lines" {
					continue
				}
				found = true
				if !strings.Contains(w.Message, "1 line") {
					t.Errorf("warning should report 1 line, got: %s", w.Message)
				}
			}
			if !found {
				t.Errorf("expected an oversized_lines warning, got: %+v", result.Warnings)
			}
			for _, w := range result.Warnings {
				if w.Type == "invalid_ips_skipped" {
					t.Errorf("oversized/blank lines must not be reported as invalid IPs: %s", w.Message)
				}
			}
		})
	}
}
