package cli

import (
	"bytes"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/iputils"
	"github.com/ChristianF88/flokbn/output"
	"github.com/ChristianF88/flokbn/version"
	cli "github.com/urfave/cli/v2"
)

func TestParseFlexibleTime(t *testing.T) {
	tests := []struct {
		input         string
		want          time.Time
		wantHasOffset bool
		wantOffsetSec int // expected zone offset (only meaningful when wantHasOffset)
		wantErr       bool
	}{
		{
			input: "2024-06-01 13:45",
			want:  time.Date(2024, 6, 1, 13, 45, 0, 0, time.UTC),
		},
		{
			input: "2024-06-01 13",
			want:  time.Date(2024, 6, 1, 13, 0, 0, 0, time.UTC),
		},
		{
			input: "2024-06-01",
			want:  time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
		},
		// URGENT-09 offset-bearing layouts: parsed as a true instant with an
		// explicit offset flag.
		{
			input:         "2024-06-01 13:45 +0100",
			want:          time.Date(2024, 6, 1, 13, 45, 0, 0, time.FixedZone("", 3600)),
			wantHasOffset: true,
			wantOffsetSec: 3600,
		},
		{
			input:         "2024-06-01 13 -0700",
			want:          time.Date(2024, 6, 1, 13, 0, 0, 0, time.FixedZone("", -7*3600)),
			wantHasOffset: true,
			wantOffsetSec: -7 * 3600,
		},
		{
			input:         "2024-06-01 +0200",
			want:          time.Date(2024, 6, 1, 0, 0, 0, 0, time.FixedZone("", 2*3600)),
			wantHasOffset: true,
			wantOffsetSec: 2 * 3600,
		},
		{
			input:   "2024/06/01",
			wantErr: true,
		},
		{
			input:   "2024-06-01 13:45:00",
			wantErr: true,
		},
		{
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		got, hasOffset, err := parseFlexibleTime(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseFlexibleTime(%q) expected error, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseFlexibleTime(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if hasOffset != tt.wantHasOffset {
			t.Errorf("parseFlexibleTime(%q) hasOffset = %v, want %v", tt.input, hasOffset, tt.wantHasOffset)
		}
		// The two times must denote the same instant.
		if !got.Equal(tt.want) {
			t.Errorf("parseFlexibleTime(%q) = %v, want %v", tt.input, got, tt.want)
		}
		if tt.wantHasOffset {
			if _, off := got.Zone(); off != tt.wantOffsetSec {
				t.Errorf("parseFlexibleTime(%q) zone offset = %d, want %d", tt.input, off, tt.wantOffsetSec)
			}
		}
	}
}

// TestParseFlexibleTimeErrorIsActionable proves the invalid-time-format error
// echoes the offending value with %q AND names the accepted layouts, so the
// user can fix it without consulting docs (guiding principle: fail with a
// helpful, actionable message that states what valid looks like).
func TestParseFlexibleTimeErrorIsActionable(t *testing.T) {
	_, _, err := parseFlexibleTime("2024/06/01")
	if err == nil {
		t.Fatal("expected error for bad time format, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, `"2024/06/01"`) {
		t.Errorf("error should quote the offending value, got: %q", msg)
	}
	for _, want := range []string{"YYYY-MM-DD", "YYYY-MM-DD HH", "YYYY-MM-DD HH:MM", "±HHMM"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should name accepted layout %q, got: %q", want, msg)
		}
	}
}

// TestValidateConfigModeFlagsNamesOffenders proves that combining --config with
// a disallowed flag fails immediately with a message that names BOTH the
// offending flag(s) the user set AND the allowed set, with no leaked Go slice.
func TestValidateConfigModeFlagsNamesOffenders(t *testing.T) {
	// static config mode allows only tui/compact/plain; --logfile and --port are
	// disallowed and should be reported as offenders.
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name: "static",
				Flags: []cli.Flag{
					configFlag, tuiFlag, compactFlag, plainFlag,
					logfileFlag, portFlag,
				},
				Action: func(c *cli.Context) error {
					return validateConfigModeFlags(c, []string{"tui", "compact", "plain"})
				},
			},
		},
	}
	err := app.Run([]string{"flokbn", "static", "--config", "x.toml", "--logfile", "a.log", "--port", "9000"})
	if err == nil {
		t.Fatal("expected error for disallowed flags in config mode, got nil")
	}
	msg := err.Error()
	// Offenders are named (deterministic flagsToCheck order: port before logfile).
	for _, want := range []string{`"--port"`, `"--logfile"`} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should name offender %s, got: %q", want, msg)
		}
	}
	// Allowed set is listed.
	for _, want := range []string{`"--tui"`, `"--compact"`, `"--plain"`} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should list allowed flag %s, got: %q", want, msg)
		}
	}
	// No leaked Go slice formatting.
	if strings.Contains(msg, "[") || strings.Contains(msg, "]") {
		t.Errorf("error should not leak a Go slice literal, got: %q", msg)
	}
}

// TestOutputResultSuccess proves outputResult now returns an error value (nil on
// the happy path) so callers can propagate a non-zero exit on marshal failure
// (MSG-03 item 4). The plain path has no marshal step and must return nil too.
func TestOutputResultSuccess(t *testing.T) {
	out := &output.JSONOutput{}
	for _, oc := range []OutputConfig{
		{},              // pretty JSON
		{Compact: true}, // compact JSON
		{Plain: true},   // plain text (no marshal)
	} {
		// Discard stdout to keep test output clean.
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		done := make(chan struct{})
		go func() { io.Copy(io.Discard, r); close(done) }()

		err := outputResult(out, oc)

		w.Close()
		os.Stdout = oldStdout
		<-done

		if err != nil {
			t.Errorf("outputResult(%+v) = %v, want nil", oc, err)
		}
	}
}

func TestCIDRValidation(t *testing.T) {
	tests := []struct {
		name     string
		cidrs    []string
		expected bool
	}{
		{
			name:     "Valid IPv4 CIDR",
			cidrs:    []string{"192.168.1.0/24"},
			expected: true,
		},
		{
			name:     "IPv6 CIDR rejected",
			cidrs:    []string{"2001:db8::/32"},
			expected: false,
		},
		{
			name:     "Multiple valid CIDRs",
			cidrs:    []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"},
			expected: true,
		},
		{
			name:     "Invalid CIDR format",
			cidrs:    []string{"192.168.1.0/33"},
			expected: false,
		},
		{
			name:     "Invalid IP address",
			cidrs:    []string{"256.256.256.256/24"},
			expected: false,
		},
		{
			name:     "Missing subnet mask",
			cidrs:    []string{"192.168.1.0"},
			expected: true, // IsValidCidrOrIp accepts individual IPs
		},
		{
			name:     "Mixed valid and invalid",
			cidrs:    []string{"192.168.1.0/24", "invalid-cidr"},
			expected: false,
		},
		{
			name:     "Empty string",
			cidrs:    []string{""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allValid := true
			for _, cidr := range tt.cidrs {
				if !iputils.IsValidCidrOrIP(cidr) {
					allValid = false
					break
				}
			}
			if allValid != tt.expected {
				t.Errorf("CIDR validation for %v = %v, want %v", tt.cidrs, allValid, tt.expected)
			}
		})
	}
}

func TestStaticCommandValidation(t *testing.T) {
	// Create a temporary test log file
	tmpFile, err := os.CreateTemp("", "test_log_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write some test data
	tmpFile.WriteString("2024-01-01 12:00:00 192.168.1.1\n")
	tmpFile.Close()

	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMatch  string
	}{
		{
			name: "Valid static command with CIDR",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--clusterArgSets", "1000,24,32,0.2",
				"--rangesCidr", "192.168.1.0/24"},
			expectError: false,
		},
		{
			name: "Multiple valid CIDRs",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--clusterArgSets", "1000,24,32,0.2",
				"--rangesCidr", "192.168.1.0/24",
				"--rangesCidr", "10.0.0.0/8"},
			expectError: false,
		},
		// CFG-02: the "Invalid CIDR range" and "Missing log file" cases moved to
		// SUBPROCESS execution (TestStaticCommandValidation_BarrierRouted) — they
		// now route through the pre-work barrier whose cli.Exit("",1) fires
		// os.Exit(1) INSIDE App.Run, which would kill this in-process test binary.
		// Only the TIER-1 hard-return case (clusterArgSets arity) and the valid
		// runs stay in-process here.
		{
			name: "Invalid cluster argument sets",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--clusterArgSets", "1000,24,32"},
			expectError: true,
			errorMatch:  "invalid clusterArgSets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture output
			oldStdout := os.Stdout
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stdout = w
			os.Stderr = w

			// Note: We should not reset flag.CommandLine as it interferes with benchmark tests
			// Instead, we'll work with the existing command line state

			var capturedOutput bytes.Buffer
			done := make(chan bool)
			go func() {
				buf := make([]byte, 1024)
				for {
					n, err := r.Read(buf)
					if err != nil {
						break
					}
					capturedOutput.Write(buf[:n])
				}
				done <- true
			}()

			// Run the CLI command
			err := App.Run(tt.args)

			// Restore output
			w.Close()
			os.Stdout = oldStdout
			os.Stderr = oldStderr
			<-done

			output := capturedOutput.String()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none. Output: %s", output)
				} else if tt.errorMatch != "" && !strings.Contains(err.Error(), tt.errorMatch) && !strings.Contains(output, tt.errorMatch) {
					t.Errorf("Expected error to contain '%s', got: %v. Output: %s", tt.errorMatch, err, output)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v. Output: %s", err, output)
				}
			}
		})
	}
}

// TestEmptyLogFileIsRequired is a regression test for the misleading
// "logfile does not exist:" (blank path) error: an empty logFile must report
// "logFile is required", not fall through to the os.Stat "does not exist" path.
// Both cases run as a SUBPROCESS so the empty-config path enumerates at the
// barrier (whose cli.Exit fires os.Exit(1)) without killing the test binary.
func TestEmptyLogFileIsRequired(t *testing.T) {
	// Config mode surfaces the TOML key `logFile`: an empty [static] logFile is
	// recorded by handleStaticConfigMode and enumerates at the barrier.
	t.Run("config mode names logFile", func(t *testing.T) {
		dir := t.TempDir()
		body := "[static]\n[static.t]\nclusterArgSets = [[1, 0, 32, 1.0]]\n"
		cfg := writeFile(t, dir, "config.toml", body)
		stdout, stderr, code := runFlokbn(t, "static", "--config", cfg)
		assertReportNoAnalysis(t, stdout, stderr, code)
		if !strings.Contains(stderr, "logFile is required") {
			t.Errorf("expected 'logFile is required' in report, got:\n%s", stderr)
		}
		if strings.Contains(stderr, "does not exist") {
			t.Errorf("empty logFile must not produce a 'does not exist' error, got:\n%s", stderr)
		}
	})
	// Flags mode surfaces the CLI `--logfile`: an unset flag is a hard return
	// from handleStaticFlagsMode before the config is ever built.
	t.Run("flags mode names --logfile", func(t *testing.T) {
		_, stderr, code := runFlokbn(t, "static", "--clusterArgSets", "1,0,32,0.1")
		if code == 0 {
			t.Fatal("expected non-zero exit for missing --logfile")
		}
		if !strings.Contains(stderr, "--logfile is required") {
			t.Errorf("expected '--logfile is required', got:\n%s", stderr)
		}
		if strings.Contains(stderr, "does not exist") {
			t.Errorf("missing --logfile must not produce a 'does not exist' error, got:\n%s", stderr)
		}
	})
}

func TestCLIFlags(t *testing.T) {
	// Test that all expected flags are present
	staticCmd := App.Commands[1] // static command is second

	expectedFlags := []string{"logfile", "logFormat", "startTime", "endTime", "useragentRegex",
		"endpointRegex", "clusterArgSets", "rangesCidr"}

	for _, expectedFlag := range expectedFlags {
		found := false
		for _, flag := range staticCmd.Flags {
			if flag.Names()[0] == expectedFlag {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected flag '%s' not found in static command", expectedFlag)
		}
	}
}

// TestEnhancedCLIArguments tests the new CLI arguments for feature parity with config mode
func TestEnhancedCLIArguments(t *testing.T) {
	// Create a temporary log file for testing
	tmpFile, err := os.CreateTemp("", "test_log_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write sample log data
	sampleLog := `127.0.0.1 - - [01/Jan/2024:12:00:00 +0000] "GET /api/test HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (compatible; bot)"
192.168.1.100 - - [01/Jan/2024:12:01:00 +0000] "POST /admin/login HTTP/1.1" 200 512 "-" "curl/7.68.0"`
	tmpFile.WriteString(sampleLog)
	tmpFile.Close()

	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMatch  string
	}{
		{
			name: "User agent regex filter",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--useragentRegex", ".*bot.*",
				"--clusterArgSets", "1,1,32,0.1"},
			expectError: false,
		},
		{
			name: "Endpoint regex filter",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--endpointRegex", "/api/.*",
				"--clusterArgSets", "1,1,32,0.1"},
			expectError: false,
		},
		{
			name: "Custom log format",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--logFormat", "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\"",
				"--clusterArgSets", "1,1,32,0.1"},
			expectError: false,
		},
		// CFG-02: the "Invalid user agent regex" and "Invalid endpoint regex"
		// cases moved to SUBPROCESS execution
		// (TestStaticCommandValidation_BarrierRouted) — a bad regex now routes
		// into cfg.diags and aborts at the barrier (os.Exit(1) inside App.Run),
		// which would kill this in-process test binary.
		{
			name: "Combined filters and time range",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--useragentRegex", ".*Mozilla.*",
				"--endpointRegex", "/api/.*",
				"--startTime", "2024-01-01",
				"--endTime", "2024-12-31",
				"--clusterArgSets", "1,1,32,0.1"},
			expectError: false,
		},
		{
			name: "Plain output mode",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--clusterArgSets", "1,1,32,0.1",
				"--plain"},
			expectError: false,
		},
		{
			name: "Plain output with compact (should work)",
			args: []string{"flokbn", "static",
				"--logfile", tmpFile.Name(),
				"--clusterArgSets", "1,1,32,0.1",
				"--plain",
				"--compact"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture output
			oldStdout := os.Stdout
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stdout = w
			os.Stderr = w

			// Note: We should not reset flag.CommandLine as it interferes with benchmark tests
			// Instead, we'll work with the existing command line state

			var capturedOutput bytes.Buffer
			done := make(chan bool)
			go func() {
				buf := make([]byte, 1024)
				for {
					n, err := r.Read(buf)
					if err != nil {
						break
					}
					capturedOutput.Write(buf[:n])
				}
				done <- true
			}()

			// Run the CLI command
			err := App.Run(tt.args)

			// Restore output
			w.Close()
			os.Stdout = oldStdout
			os.Stderr = oldStderr
			<-done

			output := capturedOutput.String()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none. Output: %s", output)
				} else if tt.errorMatch != "" && !strings.Contains(err.Error(), tt.errorMatch) && !strings.Contains(output, tt.errorMatch) {
					t.Errorf("Expected error to contain '%s', got: %v. Output: %s", tt.errorMatch, err, output)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v. Output: %s", err, output)
				}
			}
		})
	}
}

// TestRegexValidation tests the regex compilation validation
func TestRegexValidation(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		valid   bool
	}{
		{"Valid user agent regex", ".*bot.*", true},
		{"Valid endpoint regex", "/api/.*", true},
		{"Valid complex regex", "^(GET|POST).*", true},
		{"Invalid regex - unclosed bracket", "[invalid", false},
		{"Invalid regex - invalid quantifier", "*invalid", false},
		{"Empty regex", "", true}, // Empty should be valid (no filtering)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := regexp.Compile(tt.pattern)
			isValid := err == nil

			if isValid != tt.valid {
				t.Errorf("Pattern '%s' validity expected %v, got %v. Error: %v",
					tt.pattern, tt.valid, isValid, err)
			}
		})
	}
}

// TestVersionPrinterSurfacesCommit verifies that the custom VersionPrinter
// surfaces version.Commit (and the version + build date) in the CLI's
// --version / version output. This is a regression test for URGENT-19:
// version.Commit was previously set via ldflags but never read.
func TestVersionPrinterSurfacesCommit(t *testing.T) {
	if cli.VersionPrinter == nil {
		t.Fatal("cli.VersionPrinter is nil; expected custom printer set in init()")
	}

	// Capture stdout, which the custom VersionPrinter writes to via fmt.Printf.
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	cli.VersionPrinter(nil)

	w.Close()
	os.Stdout = origStdout

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read captured output: %v", err)
	}
	output := string(out)

	if !strings.Contains(output, version.Commit) {
		t.Errorf("version output missing commit %q; got: %q", version.Commit, output)
	}
	if !strings.Contains(output, version.Version) {
		t.Errorf("version output missing version %q; got: %q", version.Version, output)
	}
	if !strings.Contains(output, version.Date) {
		t.Errorf("version output missing date %q; got: %q", version.Date, output)
	}
	if !strings.Contains(output, "commit:") {
		t.Errorf("version output missing 'commit:' label; got: %q", output)
	}
}
