package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ChristianF88/flokbn/config"
)

// writeBasicAccessLog writes a tiny valid IPv4 access log compatible with the
// default static log format and returns its path.
func writeBasicAccessLog(t *testing.T, dir string) string {
	t.Helper()
	logFile := filepath.Join(dir, "access.log")
	logContent := `192.168.1.100 - - [01/Jan/2023:12:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.101 - - [01/Jan/2023:12:00:01 +0000] "GET /a HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.102 - - [01/Jan/2023:12:00:02 +0000] "GET /b HTTP/1.1" 200 1234 "-" "BadBot/1.0"
`
	if err := os.WriteFile(logFile, []byte(logContent), 0644); err != nil {
		t.Fatalf("failed to write access log: %v", err)
	}
	return logFile
}

// TestStaticUnreadableUAWhitelistFailsLoud is the AUDIT-09 regression test:
// when a UA whitelist is CONFIGURED but unreadable, the default IP-only fast
// path of Static() must surface the matcher load error loudly (non-nil error +
// "useragent_matcher_create" in the JSON output) rather than silently skipping
// all UA filtering. No per-trie regex/time filter is set, so the fast path is
// selected — this is exactly the buggy branch.
func TestStaticUnreadableUAWhitelistFailsLoud(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses file-mode permissions; cannot force an open failure via chmod")
	}

	tempDir := t.TempDir()
	logFile := writeBasicAccessLog(t, tempDir)

	// A UA whitelist file made unreadable forces os.Open to fail inside
	// CreateUserAgentMatcher -> (nil, err).
	uaWhitelistFile := filepath.Join(tempDir, "ua_whitelist.txt")
	if err := os.WriteFile(uaWhitelistFile, []byte("Mozilla/5.0\n"), 0644); err != nil {
		t.Fatalf("failed to write UA whitelist file: %v", err)
	}
	if err := os.Chmod(uaWhitelistFile, 0000); err != nil {
		t.Fatalf("failed to chmod UA whitelist file: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(uaWhitelistFile, 0644) })

	cfg := &config.Config{
		Global: &config.GlobalConfig{
			UserAgentWhitelist: uaWhitelistFile,
		},
		Static: &config.StaticConfig{
			LogFile: logFile,
			// Default static format (%h last) keeps this on the IP-only fast path.
		},
		StaticTries: map[string]*config.TrieConfig{
			// NO UserAgentRegex / EndpointRegex / StartTime / EndTime: must not
			// force needsNonIPFields=true, otherwise the full path masks the bug.
			"t": {
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 2, MinDepth: 24, MaxDepth: 24, MeanSubnetDifference: 0.5},
				},
			},
		},
	}

	result, err := Static(cfg)
	if err == nil {
		t.Fatal("expected a non-nil error when the configured UA whitelist is unreadable, got nil")
	}
	if result == nil {
		t.Fatal("expected a non-nil result even on the loud-error path")
	}

	found := false
	for _, e := range result.Errors {
		if e.Type == "useragent_matcher_create" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected JSON output to contain an error of type %q; errors=%v",
			"useragent_matcher_create", result.Errors)
	}
}

// TestStaticUnreadableUABlacklistFailsLoud mirrors the whitelist case for a
// configured-but-unreadable UA blacklist file.
func TestStaticUnreadableUABlacklistFailsLoud(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses file-mode permissions; cannot force an open failure via chmod")
	}

	tempDir := t.TempDir()
	logFile := writeBasicAccessLog(t, tempDir)

	uaBlacklistFile := filepath.Join(tempDir, "ua_blacklist.txt")
	if err := os.WriteFile(uaBlacklistFile, []byte("BadBot/1.0\n"), 0644); err != nil {
		t.Fatalf("failed to write UA blacklist file: %v", err)
	}
	if err := os.Chmod(uaBlacklistFile, 0000); err != nil {
		t.Fatalf("failed to chmod UA blacklist file: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(uaBlacklistFile, 0644) })

	cfg := &config.Config{
		Global: &config.GlobalConfig{
			UserAgentBlacklist: uaBlacklistFile,
		},
		Static: &config.StaticConfig{
			LogFile: logFile,
		},
		StaticTries: map[string]*config.TrieConfig{
			"t": {
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 2, MinDepth: 24, MaxDepth: 24, MeanSubnetDifference: 0.5},
				},
			},
		},
	}

	result, err := Static(cfg)
	if err == nil {
		t.Fatal("expected a non-nil error when the configured UA blacklist is unreadable, got nil")
	}
	found := false
	for _, e := range result.Errors {
		if e.Type == "useragent_matcher_create" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected JSON output to contain an error of type %q; errors=%v",
			"useragent_matcher_create", result.Errors)
	}
}

// TestStaticWithRequestsUnreadableUAWhitelistFailsLoud is the MSG-01 full-path
// regression (AUDIT-09 residual): StaticWithRequests (the path used by --plot and
// --tui) previously handled a configured-but-unreadable UA whitelist by AddError +
// continue, then still wrote a (wrong) ban file and exited 0. It must now fail loud
// — return a non-nil error with "useragent_matcher_create" present — BEFORE any
// jail/ban-file side effects. We point Global.JailFile/BanFile at temp paths and
// assert neither file is created, proving the early return precedes the disk writes.
func TestStaticWithRequestsUnreadableUAWhitelistFailsLoud(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses file-mode permissions; cannot force an open failure via chmod")
	}

	tempDir := t.TempDir()
	logFile := writeBasicAccessLog(t, tempDir)

	uaWhitelistFile := filepath.Join(tempDir, "ua_whitelist.txt")
	if err := os.WriteFile(uaWhitelistFile, []byte("Mozilla/5.0\n"), 0644); err != nil {
		t.Fatalf("failed to write UA whitelist file: %v", err)
	}
	if err := os.Chmod(uaWhitelistFile, 0000); err != nil {
		t.Fatalf("failed to chmod UA whitelist file: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(uaWhitelistFile, 0644) })

	// Side-effect targets: must NOT be created if the fail-loud return fires
	// before ProcessJailWithWhitelist.
	jailFile := filepath.Join(tempDir, "jail.json")
	banFile := filepath.Join(tempDir, "ban.txt")

	cfg := &config.Config{
		Global: &config.GlobalConfig{
			UserAgentWhitelist: uaWhitelistFile,
			JailFile:           jailFile,
			BanFile:            banFile,
		},
		Static: &config.StaticConfig{
			LogFile: logFile,
		},
		StaticTries: map[string]*config.TrieConfig{
			// A per-trie filter (UserAgentRegex) is set so that even if a caller
			// reached this through Static()'s dispatch it would pick the full path;
			// here we call StaticWithRequests directly, which is always the full path.
			"t": {
				UserAgentRegex: "Mozilla",
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 2, MinDepth: 24, MaxDepth: 24, MeanSubnetDifference: 0.5},
				},
			},
		},
	}

	result, _, err := StaticWithRequests(cfg)
	if err == nil {
		t.Fatal("expected a non-nil error from StaticWithRequests when the configured UA whitelist is unreadable, got nil")
	}
	if result == nil {
		t.Fatal("expected a non-nil result even on the loud-error path")
	}

	found := false
	for _, e := range result.Errors {
		if e.Type == "useragent_matcher_create" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected JSON output to contain an error of type %q; errors=%v",
			"useragent_matcher_create", result.Errors)
	}

	// The fail-loud return must precede the jail/ban-file writes: neither file
	// may exist after the call.
	if _, statErr := os.Stat(banFile); !os.IsNotExist(statErr) {
		t.Errorf("ban file %q must NOT be written when the UA matcher fails to load (stat err=%v)", banFile, statErr)
	}
	if _, statErr := os.Stat(jailFile); !os.IsNotExist(statErr) {
		t.Errorf("jail file %q must NOT be written when the UA matcher fails to load (stat err=%v)", jailFile, statErr)
	}
}

// TestStaticWithRequestsUnreadableUABlacklistFailsLoud mirrors the whitelist case
// for a configured-but-unreadable UA blacklist file on the full path.
func TestStaticWithRequestsUnreadableUABlacklistFailsLoud(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses file-mode permissions; cannot force an open failure via chmod")
	}

	tempDir := t.TempDir()
	logFile := writeBasicAccessLog(t, tempDir)

	uaBlacklistFile := filepath.Join(tempDir, "ua_blacklist.txt")
	if err := os.WriteFile(uaBlacklistFile, []byte("BadBot/1.0\n"), 0644); err != nil {
		t.Fatalf("failed to write UA blacklist file: %v", err)
	}
	if err := os.Chmod(uaBlacklistFile, 0000); err != nil {
		t.Fatalf("failed to chmod UA blacklist file: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(uaBlacklistFile, 0644) })

	jailFile := filepath.Join(tempDir, "jail.json")
	banFile := filepath.Join(tempDir, "ban.txt")

	cfg := &config.Config{
		Global: &config.GlobalConfig{
			UserAgentBlacklist: uaBlacklistFile,
			JailFile:           jailFile,
			BanFile:            banFile,
		},
		Static: &config.StaticConfig{
			LogFile: logFile,
		},
		StaticTries: map[string]*config.TrieConfig{
			"t": {
				UserAgentRegex: "Mozilla",
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 2, MinDepth: 24, MaxDepth: 24, MeanSubnetDifference: 0.5},
				},
			},
		},
	}

	result, _, err := StaticWithRequests(cfg)
	if err == nil {
		t.Fatal("expected a non-nil error from StaticWithRequests when the configured UA blacklist is unreadable, got nil")
	}
	if result == nil {
		t.Fatal("expected a non-nil result even on the loud-error path")
	}

	found := false
	for _, e := range result.Errors {
		if e.Type == "useragent_matcher_create" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected JSON output to contain an error of type %q; errors=%v",
			"useragent_matcher_create", result.Errors)
	}

	if _, statErr := os.Stat(banFile); !os.IsNotExist(statErr) {
		t.Errorf("ban file %q must NOT be written when the UA matcher fails to load (stat err=%v)", banFile, statErr)
	}
	if _, statErr := os.Stat(jailFile); !os.IsNotExist(statErr) {
		t.Errorf("jail file %q must NOT be written when the UA matcher fails to load (stat err=%v)", jailFile, statErr)
	}
}

// TestStaticOmittedUAListFastPathIntact is the companion acceptance check:
// with NO UA list configured (and no per-trie filters), CreateUserAgentMatcher
// returns (nil, nil), so Static() must NOT error and must still run the IP-only
// fast path to completion, producing trie results.
func TestStaticOmittedUAListFastPathIntact(t *testing.T) {
	tempDir := t.TempDir()
	logFile := writeBasicAccessLog(t, tempDir)

	cfg := &config.Config{
		// No Global UA whitelist/blacklist configured.
		Static: &config.StaticConfig{
			LogFile: logFile,
		},
		StaticTries: map[string]*config.TrieConfig{
			"t": {
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 2, MinDepth: 24, MaxDepth: 24, MeanSubnetDifference: 0.5},
				},
			},
		},
	}

	result, err := Static(cfg)
	if err != nil {
		t.Fatalf("expected nil error for omitted UA list, got %v", err)
	}
	if result == nil {
		t.Fatal("expected a non-nil result")
	}
	for _, e := range result.Errors {
		if e.Type == "useragent_matcher_create" {
			t.Errorf("did not expect a useragent_matcher_create error for an omitted UA list")
		}
	}
	if len(result.Tries) != 1 {
		t.Errorf("expected 1 trie result on the fast path, got %d", len(result.Tries))
	}
}
