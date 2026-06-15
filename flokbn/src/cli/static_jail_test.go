package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runAppCaptured runs the CLI App with stdout/stderr captured so test output
// stays clean. Returns the combined output and the App error.
func runAppCaptured(t *testing.T, args []string) (string, error) {
	t.Helper()

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	os.Stdout = w
	os.Stderr = w

	var captured bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				captured.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	runErr := App.Run(args)

	w.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	<-done

	return captured.String(), runErr
}

// TestStaticFlagsModeJailsDetections is a regression test for the static
// CLI-flags mode never jailing detections: handleStaticFlagsMode used to build
// the TrieConfig without UseForJail, so ProcessJailWithWhitelist collected no
// CIDRs and `flokbn static --jailFile X --banFile Y --clusterArgSets ...` wrote
// a header-only ban file and no jail file. CLI-provided cluster sets must
// default to UseForJail=true (parity with live flags mode).
func TestStaticFlagsModeJailsDetections(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "cluster.log")
	jailFile := filepath.Join(tmpDir, "jail.json")
	banFile := filepath.Join(tmpDir, "ban.txt")

	// 5000 IPs in 10.20.0.0/16 — enough to form a detectable cluster.
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		v := i + 1
		ip := fmt.Sprintf("10.20.%d.%d", v/256, v%256)
		fmt.Fprintf(&b, "%s - - [01/Feb/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 100 \"-\" \"test\"\n", ip)
	}
	if err := os.WriteFile(logFile, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}

	output, err := runAppCaptured(t, []string{"flokbn", "static",
		"--logfile", logFile,
		"--logFormat", "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\"",
		"--clusterArgSets", "1000,16,24,0.2",
		"--jailFile", jailFile,
		"--banFile", banFile,
		"--plain"})
	if err != nil {
		t.Fatalf("static command failed: %v. Output: %s", err, output)
	}

	// The detected 10.20.x.x cluster must have been jailed.
	jailData, err := os.ReadFile(jailFile)
	if err != nil {
		t.Fatalf("jail file was not created (detections were not jailed): %v", err)
	}
	if !strings.Contains(string(jailData), "10.20.") {
		t.Errorf("jail file does not contain the detected 10.20.x.x range. Content: %s", jailData)
	}

	// The ban file must contain the banned range, not just the header.
	banData, err := os.ReadFile(banFile)
	if err != nil {
		t.Fatalf("ban file was not created: %v", err)
	}
	if !strings.Contains(string(banData), "10.20.") {
		t.Errorf("ban file does not contain the detected 10.20.x.x range (header-only ban file). Content: %s", banData)
	}
}

// TestLiveCommandRejectsStaticOnlyFlags verifies that the live command does
// not accept static-only output/analysis flags. These used to be defined on
// live but had no effect there; they must now be rejected just like --tui.
func TestLiveCommandRejectsStaticOnlyFlags(t *testing.T) {
	staticOnlyArgs := [][]string{
		{"flokbn", "live", "--plain"},
		{"flokbn", "live", "--compact"},
		{"flokbn", "live", "--rangesCidr", "10.0.0.0/8"},
		{"flokbn", "live", "--plotPath", "/tmp/plot.png"},
		{"flokbn", "live", "--tui"},
	}

	for _, args := range staticOnlyArgs {
		t.Run(args[2], func(t *testing.T) {
			output, err := runAppCaptured(t, args)
			if err == nil {
				t.Errorf("expected live to reject %s, but it was accepted. Output: %s", args[2], output)
			} else if !strings.Contains(err.Error(), "flag provided but not defined") {
				t.Errorf("expected 'flag provided but not defined' error for %s, got: %v", args[2], err)
			}
		})
	}
}
