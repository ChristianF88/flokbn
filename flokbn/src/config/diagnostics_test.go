package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig writes content to a fresh temp config file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// TestDiagnosticsCollectAllSingleTrieTwoErrors proves the per-trie checks do NOT
// early-return: ONE trie with BOTH a bad startTime AND a bad endTime yields TWO
// messages. The cross-trie Len==3 test is insufficient for this — it would pass
// even if startTime short-circuited the endTime check within a single trie.
func TestDiagnosticsCollectAllSingleTrieTwoErrors(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
[static.solo]
startTime = "not-a-time"
endTime = "also-bad"
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	d := cfg.Validate(StaticMode)
	if d.Len() != 2 {
		t.Fatalf("expected 2 diagnostics from one trie, got %d:\n%s", d.Len(), d.Report())
	}
	r := d.Report()
	if !strings.Contains(r, "[static.solo] invalid startTime") {
		t.Errorf("missing startTime diagnostic:\n%s", r)
	}
	if !strings.Contains(r, "[static.solo] invalid endTime") {
		t.Errorf("missing endTime diagnostic:\n%s", r)
	}
}

// TestDiagnosticsCollectAllContent checks CONTENT (not just Len): a bad
// startTime in trie a, a bad endTime in trie b, and an inverted range in trie c
// each produce their specific expected line.
func TestDiagnosticsCollectAllContent(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
[static.a]
startTime = "bad-start"

[static.b]
endTime = "bad-end"

[static.c]
startTime = "2025-01-15T00:00:00Z"
endTime = "2025-01-01T00:00:00Z"
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	d := cfg.Validate(StaticMode)
	if d.Len() != 3 {
		t.Fatalf("expected 3 diagnostics, got %d:\n%s", d.Len(), d.Report())
	}
	r := d.Report()
	for _, want := range []string{
		`[static.a] invalid startTime "bad-start"`,
		`[static.b] invalid endTime "bad-end"`,
		`[static.c] endTime "2025-01-01T00:00:00Z" is before startTime "2025-01-15T00:00:00Z"`,
	} {
		if !strings.Contains(r, want) {
			t.Errorf("report missing %q:\n%s", want, r)
		}
	}
}

// TestDiagnosticsDeterministicOrdering runs LoadConfig+Validate over many fresh
// cycles (fresh Go map => randomized iteration order PER RUN) and asserts the
// report is BYTE-IDENTICAL to a hardcoded fully-sorted expected string every
// time. Calling Report() N times on ONE diags would NOT catch a missing sort
// (msgs order is fixed once built); only fresh map iteration exposes it. The
// sections are chosen so their sorted order differs from any plausible
// insertion order.
func TestDiagnosticsDeterministicOrdering(t *testing.T) {
	content := `
[static.zulu]
startTime = "z-bad"

[static.alpha]
startTime = "a-bad"

[static.mike]
startTime = "m-bad"
`
	want := "configuration errors (3):\n" +
		`1. [static.alpha] invalid startTime "a-bad": want RFC3339 (e.g. 2025-01-01T00:00:00Z)` + "\n" +
		`2. [static.mike] invalid startTime "m-bad": want RFC3339 (e.g. 2025-01-01T00:00:00Z)` + "\n" +
		`3. [static.zulu] invalid startTime "z-bad": want RFC3339 (e.g. 2025-01-01T00:00:00Z)` + "\n"

	for i := 0; i < 30; i++ {
		cfg, err := LoadConfig(writeConfig(t, content))
		if err != nil {
			t.Fatalf("cycle %d LoadConfig: %v", i, err)
		}
		got := cfg.Validate(StaticMode).Report()
		if got != want {
			t.Fatalf("cycle %d report not byte-identical to sorted expected.\nwant:\n%s\ngot:\n%s", i, want, got)
		}
	}
}

// TestDiagnosticsGrammarLock pins both message classes verbatim: the
// single-field "invalid <key>" MSG-02 line and the cross-field range line.
func TestDiagnosticsGrammarLock(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
[static.fmt]
startTime = "2026-02-04T12:00:0"

[static.rng]
startTime = "2025-02-01T00:00:00Z"
endTime = "2025-01-01T00:00:00Z"
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	r := cfg.Validate(StaticMode).Report()
	const singleField = `[static.fmt] invalid startTime "2026-02-04T12:00:0": want RFC3339 (e.g. 2025-01-01T00:00:00Z)`
	const crossField = `[static.rng] endTime "2025-01-01T00:00:00Z" is before startTime "2025-02-01T00:00:00Z": want endTime >= startTime`
	if !strings.Contains(r, singleField) {
		t.Errorf("single-field grammar mismatch; want substring:\n%s\nin:\n%s", singleField, r)
	}
	if !strings.Contains(r, crossField) {
		t.Errorf("cross-field grammar mismatch; want substring:\n%s\nin:\n%s", crossField, r)
	}
}

// TestDiagnosticsSanitizeNewline proves an embedded newline in a user value is
// escaped (strconv.Quote), so it cannot forge a fake numbered/header line: the
// report line count stays header + N.
func TestDiagnosticsSanitizeNewline(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
[static.nl]
startTime = "a\nb"
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	d := cfg.Validate(StaticMode)
	r := d.Report()
	// One diagnostic => exactly header + 1 numbered line => 2 lines, each ending
	// in "\n" => trailing "" split element => 3 parts.
	parts := strings.Split(r, "\n")
	if len(parts) != 3 || parts[2] != "" {
		t.Fatalf("embedded newline broke the one-line-per-error contract; report:\n%q", r)
	}
	// The raw newline must NOT appear inside the echoed value; strconv.Quote
	// renders it as the two-character escape \n.
	if !strings.Contains(r, `"a\nb"`) {
		t.Errorf("expected escaped value \"a\\nb\" in report:\n%s", r)
	}
}

// TestDiagnosticsCapTruncates proves a hostile multi-KB value is truncated
// (rune-safe + ellipsis) before quoting, so the full value never lands in the
// report.
func TestDiagnosticsCapTruncates(t *testing.T) {
	huge := strings.Repeat("x", 10000)
	cfg, err := LoadConfig(writeConfig(t, fmt.Sprintf(`
[static.big]
startTime = "%s"
`, huge)))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	r := cfg.Validate(StaticMode).Report()
	if strings.Contains(r, huge) {
		t.Errorf("full 10000-byte value should not appear in the report")
	}
	if !strings.Contains(r, "…") {
		t.Errorf("expected truncation ellipsis in the report:\n%.200s", r)
	}
	if len(r) > 400 {
		t.Errorf("report unexpectedly large (%d bytes); cap not applied", len(r))
	}
}

// TestDiagnosticsEmptyBoundAccepted proves an empty startTime is accepted (the
// strictness boundary is unchanged): no diagnostic.
func TestDiagnosticsEmptyBoundAccepted(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
[static.empty]
startTime = ""
endTime = ""
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if d := cfg.Validate(StaticMode); d.HasErrors() {
		t.Errorf("empty bound must be accepted, got:\n%s", d.Report())
	}
}

// TestDiagnosticsLiveParity proves the sliding-trie parse path feeds diagnostics
// with the IDENTICAL RFC3339 layout: a [live.<win>] bad startTime is reported,
// and a [live.<win>] inverted range produces the range diagnostic.
func TestDiagnosticsLiveParity(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
[live.fmt]
startTime = "live-bad"

[live.rng]
startTime = "2025-02-01T00:00:00Z"
endTime = "2025-01-01T00:00:00Z"
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	r := cfg.Validate(LiveMode).Report()
	if !strings.Contains(r, `[live.fmt] invalid startTime "live-bad"`) {
		t.Errorf("expected live startTime diagnostic:\n%s", r)
	}
	if !strings.Contains(r, `[live.rng] endTime "2025-01-01T00:00:00Z" is before startTime "2025-02-01T00:00:00Z"`) {
		t.Errorf("expected live range diagnostic:\n%s", r)
	}
}

// TestDiagnosticsTypeErrorStaysHard proves a wrong-TYPE timestamp (int) is a
// HARD LoadConfig error (structural), NOT a diagnostic — for BOTH the trie and
// sliding-trie parse paths.
func TestDiagnosticsTypeErrorStaysHard(t *testing.T) {
	if _, err := LoadConfig(writeConfig(t, `
[static.t]
startTime = 123
`)); err == nil {
		t.Errorf("static: expected hard error for integer startTime")
	}
	if _, err := LoadConfig(writeConfig(t, `
[live.w]
startTime = 123
`)); err == nil {
		t.Errorf("live: expected hard error for integer startTime")
	}
}
