package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CFG-02: collect-all config validation. These tests prove the accumulator
// surfaces N distinct errors at once, that Validate is idempotent (copies
// cfg.diags, never mutates it), the useForJail dependency guard, the cidrRanges
// drop-from-slice invariant, AddRaw sanitation/cap, mixed-producer ordering
// determinism, the empty-logFormat fallback, and validateLiveInto nil-safety.

// TestCFG02_CollectAllStaticNErrors: one TOML with N distinct error classes
// across multiple sections yields Validate.Len()==N and the SET of substrings,
// proving NOT fail-fast.
func TestCFG02_CollectAllStaticNErrors(t *testing.T) {
	content := `
[global]
jailfile = "/x/jail.json"

[static]
logfile = "/x/access.log"

[static.t1]
useragentRegex = "[invalid"
cidrRanges = ["2001:db8::/48"]

[static.t2]
startTime = "bad-ts"
`
	cfg, err := loadConfigString(t, content)
	if err != nil {
		t.Fatalf("LoadConfig should succeed: %v", err)
	}
	d := cfg.Validate(StaticMode)
	wantSubs := []string{
		"jailfile",                   // [global] unknown key
		"logfile",                    // [static] unknown key
		"invalid useragentRegex",     // [static.t1] regex
		"IPv6 not supported",         // [static.t1] cidrRanges
		`invalid startTime "bad-ts"`, // [static.t2] timestamp
	}
	if d.Len() != len(wantSubs) {
		t.Fatalf("expected %d diagnostics, got %d:\n%s", len(wantSubs), d.Len(), d.Report())
	}
	r := d.Report()
	for _, sub := range wantSubs {
		if !strings.Contains(r, sub) {
			t.Errorf("report missing %q:\n%s", sub, r)
		}
	}
}

// TestCFG02_SingleSectionMultiError: two bad cidrRanges in one trie yield two
// diagnostics (no within-section early return).
func TestCFG02_SingleSectionMultiError(t *testing.T) {
	cfg, err := loadConfigString(t, `
[static.t]
cidrRanges = ["2001:db8::/48", "not-a-cidr"]
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	d := cfg.Validate(StaticMode)
	if d.Len() != 2 {
		t.Fatalf("expected 2 cidrRanges diagnostics, got %d:\n%s", d.Len(), d.Report())
	}
}

// TestCFG02_ValidateIdempotent: calling Validate twice yields identical Len()
// AND identical Report() (proves Validate copies cfg.diags read-only — never
// accumulates, never double-counts list files / logFormat).
func TestCFG02_ValidateIdempotent(t *testing.T) {
	for _, mode := range []RunMode{StaticMode, LiveMode} {
		cfg, err := loadConfigString(t, `
[global]
jailfile = "/x/jail.json"

[static.t]
useragentRegex = "[invalid"
startTime = "bad-ts"

[live.w]
useragentRegex = "[invalid"
startTime = "bad-ts"
`)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		d1 := cfg.Validate(mode)
		d2 := cfg.Validate(mode)
		if d1.Len() != d2.Len() {
			t.Fatalf("mode %d: Validate not idempotent: Len %d vs %d", mode, d1.Len(), d2.Len())
		}
		if d1.Report() != d2.Report() {
			t.Fatalf("mode %d: Validate not idempotent:\nfirst:\n%s\nsecond:\n%s", mode, d1.Report(), d2.Report())
		}
	}
}

// TestCFG02_NoSilentClusterRowDrop: when NO diagnostic is recorded for a trie,
// every input clusterArgSets row survives (len(returnedSets)==len(inputRows)).
func TestCFG02_NoSilentClusterRowDrop(t *testing.T) {
	cfg, err := loadConfigString(t, `
[static.t]
clusterArgSets = [[1, 0, 32, 0.1], [2, 0, 32, 0.2], [3, 0, 32, 0.3]]
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if d := cfg.Validate(StaticMode); d.HasErrors() {
		t.Fatalf("clean clusterArgSets must produce no diagnostics:\n%s", d.Report())
	}
	tc := cfg.StaticTries["t"]
	if len(tc.ClusterArgSets) != 3 {
		t.Fatalf("len(diags)==0 must imply no dropped row; got %d sets", len(tc.ClusterArgSets))
	}
}

// TestCFG02_CIDRRangesDropFromSlice: cidrRanges=[valid, IPv6, malformed] yields
// 2 diagnostics AND tc.CIDRRanges holds ONLY the valid IPv4 entry (never stores
// a bad entry — the negative-shift-panic guard).
func TestCFG02_CIDRRangesDropFromSlice(t *testing.T) {
	cfg, err := loadConfigString(t, `
[static.t]
cidrRanges = ["10.0.0.0/8", "2001:db8::/48", "not-a-cidr"]
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	d := cfg.Validate(StaticMode)
	if d.Len() != 2 {
		t.Fatalf("expected 2 cidrRanges diagnostics, got %d:\n%s", d.Len(), d.Report())
	}
	tc := cfg.StaticTries["t"]
	if len(tc.CIDRRanges) != 1 || tc.CIDRRanges[0] != "10.0.0.0/8" {
		t.Fatalf("only the valid IPv4 entry must be stored, got: %v", tc.CIDRRanges)
	}
}

// TestCFG02_DependencyGuard_ClusterRowDropClearsUseForJail: a dropped
// clusterArgSets row yields exactly ONE diagnostic (NOT a second spurious
// alignment mismatch) AND the trie's UseForJail is cleared.
func TestCFG02_DependencyGuard_ClusterRowDropClearsUseForJail(t *testing.T) {
	cfg, err := loadConfigString(t, `
[static.t]
clusterArgSets = [[1, 0, 32, 0.1], [2, 33, 32, 0.2]]
useForJail = [true, true]
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	d := cfg.Validate(StaticMode)
	if d.Len() != 1 {
		t.Fatalf("expected exactly 1 diagnostic (the row error, no spurious alignment), got %d:\n%s", d.Len(), d.Report())
	}
	if !strings.Contains(d.Report(), "minDepth") {
		t.Errorf("expected the clusterArgSets row diagnostic, got:\n%s", d.Report())
	}
	tc := cfg.StaticTries["t"]
	if tc.UseForJail != nil {
		t.Errorf("UseForJail must be cleared when clusterArgSets errored, got: %v", tc.UseForJail)
	}
}

// TestCFG02_DependencyGuard_UseForJailElementDrop: a bad useForJail element
// yields exactly the element diagnostic, NOT a spurious alignment diagnostic.
func TestCFG02_DependencyGuard_UseForJailElementDrop(t *testing.T) {
	cfg, err := loadConfigString(t, `
[static.t]
clusterArgSets = [[1, 0, 32, 0.1], [2, 0, 32, 0.2]]
useForJail = [true, "x"]
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	d := cfg.Validate(StaticMode)
	if d.Len() != 1 {
		t.Fatalf("expected exactly 1 diagnostic (the element error, no spurious alignment), got %d:\n%s", d.Len(), d.Report())
	}
	if !strings.Contains(d.Report(), "useForJail[1]") {
		t.Errorf("expected the useForJail element diagnostic, got:\n%s", d.Report())
	}
}

// TestCFG02_AddRawSanitizesNewline: a newline-bearing unknown-key name (TOML
// quoted key) is escaped so it cannot forge a fake numbered line — the
// header+N line-count invariant holds and Len() is exact.
func TestCFG02_AddRawSanitizesNewline(t *testing.T) {
	cfg, err := loadConfigString(t, `
[global]
"a\nb" = "x"
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	d := cfg.Validate(StaticMode)
	if d.Len() != 1 {
		t.Fatalf("expected exactly 1 diagnostic, got %d:\n%q", d.Len(), d.Report())
	}
	r := d.Report()
	parts := strings.Split(r, "\n")
	// header + 1 numbered line + trailing "" = 3 parts.
	if len(parts) != 3 || parts[2] != "" {
		t.Fatalf("embedded newline broke one-line-per-error; report:\n%q", r)
	}
	if !strings.Contains(r, `a\nb`) {
		t.Errorf("expected escaped key a\\nb, got:\n%q", r)
	}
}

// TestCFG02_AddRawCapsHugeKey: a multi-KB unknown-key name is truncated so the
// full value never lands in the report.
func TestCFG02_AddRawCapsHugeKey(t *testing.T) {
	huge := strings.Repeat("z", 9000)
	cfg, err := loadConfigString(t, "[global]\n\""+huge+"\" = \"x\"\n")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	r := cfg.Validate(StaticMode).Report()
	if strings.Contains(r, huge) {
		t.Errorf("full 9000-byte key should not appear in the report")
	}
	if !strings.Contains(r, "…") {
		t.Errorf("expected truncation ellipsis, got:\n%.200s", r)
	}
}

// TestCFG02_AddRawSanitizesCidrNewline: a newline-bearing cidrRanges value is
// escaped on the AddRaw path.
func TestCFG02_AddRawSanitizesCidrNewline(t *testing.T) {
	cfg, err := loadConfigString(t, `
[static.t]
cidrRanges = ["bad\nvalue"]
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	d := cfg.Validate(StaticMode)
	r := d.Report()
	parts := strings.Split(r, "\n")
	if len(parts) != 3 || parts[2] != "" {
		t.Fatalf("embedded newline broke one-line-per-error; report:\n%q", r)
	}
}

// TestCFG02_MixedAddRawOrderingDeterministic: a config mixing unknown [global]
// key + unknown [static] key + an "invalid" Add line + an IPv6 cidrRanges AddRaw
// line produces a byte-stable Report() across repeated fresh LoadConfig+Validate
// cycles (proves total-order determinism of the mixed Add/AddRaw line space
// despite map-iteration producers).
func TestCFG02_MixedAddRawOrderingDeterministic(t *testing.T) {
	content := `
[global]
gbad = "x"

[static]
sbad = "y"

[static.t]
startTime = "bad-ts"
cidrRanges = ["2001:db8::/48"]
`
	var want string
	for i := 0; i < 25; i++ {
		cfg, err := loadConfigString(t, content)
		if err != nil {
			t.Fatalf("cycle %d LoadConfig: %v", i, err)
		}
		got := cfg.Validate(StaticMode).Report()
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("cycle %d report not byte-stable.\nwant:\n%s\ngot:\n%s", i, want, got)
		}
	}
}

// TestCFG02_EmptyLogFormatPasses: a [static] section with NO logFormat key
// passes Validate with ZERO diagnostics (the empty->DefaultLogFormat fallback
// precedes ValidateFormat).
func TestCFG02_EmptyLogFormatPasses(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(logFile, []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfigString(t, `
[static]
logFile = "`+logFile+`"

[static.t]
clusterArgSets = [[1, 0, 32, 0.1]]
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if d := cfg.Validate(StaticMode); d.HasErrors() {
		t.Fatalf("empty logFormat must pass (default fallback), got:\n%s", d.Report())
	}
}

// TestCFG02_BadLogFormatDiagnostic: a logFormat missing %h produces a logFormat
// diagnostic.
func TestCFG02_BadLogFormatDiagnostic(t *testing.T) {
	cfg, err := loadConfigString(t, `
[static]
logFormat = "%s %b"

[static.t]
clusterArgSets = [[1, 0, 32, 0.1]]
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	r := cfg.Validate(StaticMode).Report()
	if !strings.Contains(r, "logFormat") {
		t.Errorf("expected logFormat diagnostic, got:\n%s", r)
	}
}

// TestCFG02_ListFileDiagnostic: a configured-but-unreadable whitelist surfaces
// a cannot-open diagnostic at Validate (both modes).
func TestCFG02_ListFileDiagnostic(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.txt")
	for _, mode := range []RunMode{StaticMode, LiveMode} {
		cfg, err := loadConfigString(t, `
[global]
whitelist = "`+missing+`"
`)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		r := cfg.Validate(mode).Report()
		if !strings.Contains(r, "cannot open") {
			t.Errorf("mode %d: expected cannot-open diagnostic, got:\n%s", mode, r)
		}
	}
}

// TestCFG02_ListFileLongLineCannotRead: a list whose longest line exceeds the
// 64KB bufio token limit surfaces a "cannot read" diagnostic (no silent
// truncation of a whitelist — a fail-open guard).
func TestCFG02_ListFileLongLineCannotRead(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	long := "10.0.0.0/8\n" + strings.Repeat("a", 70000) + "\n"
	if err := os.WriteFile(wl, []byte(long), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfigString(t, `
[global]
whitelist = "`+wl+`"
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	r := cfg.Validate(StaticMode).Report()
	if !strings.Contains(r, "cannot read") {
		t.Errorf("expected cannot-read diagnostic for an over-long line, got:\n%s", r)
	}
}

// TestCFG02_ValidateLiveNilDeref: a Config with c.Live==nil AND c.Global==nil
// AND a non-empty LiveTries reports the required-section diagnostics and does
// NOT panic.
func TestCFG02_ValidateLiveNilDeref(t *testing.T) {
	cfg := &Config{
		LiveTries: map[string]*SlidingTrieConfig{
			"w": {SlidingWindowMaxSize: 0, SlidingWindowMaxTime: 0},
		},
	}
	d := cfg.Validate(LiveMode) // must not panic
	r := d.Report()
	if !strings.Contains(r, "live config section is required") {
		t.Errorf("expected live-section diagnostic, got:\n%s", r)
	}
	if !strings.Contains(r, "global config section is required") {
		t.Errorf("expected global-section diagnostic, got:\n%s", r)
	}
}

// TestCFG02_TypeErrorsStayHard: wrong-TYPE scalars (port=int, topTalkers=string,
// readTimeout=bogus) stay HARD LoadConfig errors, NOT diagnostics.
func TestCFG02_TypeErrorsStayHard(t *testing.T) {
	cases := []struct {
		name string
		toml string
		sub  string
	}{
		{"port int", "[live]\nport = 8080\n", "port"},
		{"topTalkers string", "[live]\nport = \"8080\"\ntopTalkers = \"ten\"\n", "topTalkers"},
		{"readTimeout bogus", "[live]\nport = \"8080\"\nreadTimeout = \"bogus\"\n", "readTimeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfigString(t, tc.toml)
			if err == nil {
				t.Fatalf("expected HARD LoadConfig error, got nil")
			}
			if !strings.Contains(err.Error(), tc.sub) {
				t.Fatalf("error should mention %q, got: %v", tc.sub, err)
			}
		})
	}
}

// TestCFG02_ValidateLiveShimFirstMessageStable: the ValidateLive shim's first
// message is stable (a deterministic scalar check, not a map-ranged window).
func TestCFG02_ValidateLiveShimFirstMessageStable(t *testing.T) {
	cfg := &Config{Live: nil}
	for i := 0; i < 20; i++ {
		err := cfg.ValidateLive()
		if err == nil || !strings.Contains(err.Error(), "live config section is required") {
			t.Fatalf("cycle %d: shim first message unstable: %v", i, err)
		}
	}
}
