package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ConfigDiagnostics accumulates user-facing configuration problems collected
// during a Validate pass. It is threaded by-pointer (not a package global) so
// each Validate call owns its instance. A malformed-but-structurally-valid
// input records a message and validation continues (no fail-fast), so one pass
// surfaces every config problem at once; the pre-work barrier (cli/barrier.go)
// then reports all messages and exits before any side-effecting work.
//
// Structural/type errors (TOML syntax, wrong-typed timestamp, unreadable file)
// are not routed here — they stay hard fail-fast errors at LoadConfig time.
type ConfigDiagnostics struct {
	msgs []string
}

// diagValueCap bounds the echoed length (bytes) of a user-supplied value before
// it is quoted, so a hostile multi-megabyte TOML value cannot bloat the stderr
// report or make Report() allocation-heavy.
const diagValueCap = 120

// quoteCapped renders an untrusted user value for a diagnostic line: truncate
// (rune-safe) to diagValueCap, then strconv.Quote. The quote escapes newlines
// and other control characters so a hostile value cannot break the
// one-line-per-error contract, forge a numbered/header line, or make the
// post-sort enumeration nondeterministic.
func quoteCapped(value string) string {
	if len(value) > diagValueCap {
		// Back up to a rune start so we never emit half a multi-byte rune; the
		// U+2026 ellipsis signals truncation.
		cut := diagValueCap
		for cut > 0 && !utf8.RuneStart(value[cut]) {
			cut--
		}
		value = value[:cut] + "…"
	}
	return strconv.Quote(value)
}

// Add records a single-field "invalid <key>" diagnostic. It owns the section
// brackets: callers pass section without them (e.g. "static.t4_window") and Add
// wraps it in exactly one pair, emitting verbatim:
//
//	[<section>] invalid <key> <qvalue>: want <want>
//
// where qvalue is quoteCapped(value). The cross-field range class is AddRange.
//
// cause is the CFG-02 migration seam: CFG-01 callers pass nil (nothing appended).
func (d *ConfigDiagnostics) Add(section, key, value, want string, cause error) {
	line := fmt.Sprintf("[%s] invalid %s %s: want %s", section, key, quoteCapped(value), want)
	if cause != nil {
		line += ": " + cause.Error()
	}
	d.msgs = append(d.msgs, line)
}

// AddRange records the cross-field "endTime is before startTime" diagnostic, a
// distinct message class from Add (a parseable endTime is not "invalid"). The
// raw user literals are echoed, not the normalized RFC3339 Format, so a
// +00:00 -> Z round-trip cannot drift the message. Shape, emitted verbatim:
//
//	[<section>] endTime <qendRaw> is before startTime <qstartRaw>: want endTime >= startTime
func (d *ConfigDiagnostics) AddRange(section, endRaw, startRaw string) {
	line := fmt.Sprintf("[%s] endTime %s is before startTime %s: want endTime >= startTime",
		section, quoteCapped(endRaw), quoteCapped(startRaw))
	d.msgs = append(d.msgs, line)
}

// HasErrors reports whether any diagnostic was recorded.
func (d *ConfigDiagnostics) HasErrors() bool { return len(d.msgs) > 0 }

// Len returns the number of recorded diagnostics (for content/collect-all tests).
func (d *ConfigDiagnostics) Len() int { return len(d.msgs) }

// Report renders the diagnostics as a deterministic enumerated block: a
// "configuration errors (N):" header followed by N sorted, numbered lines. The
// sort operates on a copy so Add order stays observable to tests, and numbers
// are assigned after the sort so the enumeration is deterministic regardless of
// map iteration order.
func (d *ConfigDiagnostics) Report() string {
	sorted := make([]string, len(d.msgs))
	copy(sorted, d.msgs)
	sort.Strings(sorted)

	var b strings.Builder
	fmt.Fprintf(&b, "configuration errors (%d):\n", len(sorted))
	for i, line := range sorted {
		fmt.Fprintf(&b, "%d. %s\n", i+1, line)
	}
	return b.String()
}
