package config

import (
	"fmt"
	"sort"
	"time"
)

// DefaultSleepBetweenIterations is the pause, in seconds, between live
// detection iterations when a window does not set sleepBetweenIterations. It
// is the single default for BOTH surfaces: the --sleepBetweenIterations flag
// and an omitted TOML key (which used to mean 0, i.e. no pause at all). An
// explicit `sleepBetweenIterations = 0` is still honored.
const DefaultSleepBetweenIterations = 10

// DefaultClusterArgSets returns the cluster-arg sets used when a flags-mode run
// passes none: one tight tier that flags hot hosts and small subnets. It is the
// single source for both `static` and `live` flags mode. A fresh slice is
// returned on every call, so callers may append to or modify it.
func DefaultClusterArgSets() []ClusterArgSet {
	return []ClusterArgSet{{
		MinClusterSize:       1000,
		MinDepth:             30,
		MaxDepth:             32,
		MeanSubnetDifference: 0.2,
	}}
}

// TimeBoundFormats describes the accepted startTime/endTime syntaxes for
// diagnostics and help text.
const TimeBoundFormats = `RFC3339 (e.g. 2025-01-01T00:00:00Z) or YYYY-MM-DD, "YYYY-MM-DD HH", "YYYY-MM-DD HH:MM", each optionally with " ±HHMM"`

// timeBoundOffsetLayouts carry an explicit zone offset: the bound is compared
// as a true instant. They are tried before the zone-less layouts so a trailing
// "-0700" is not mis-parsed.
var timeBoundOffsetLayouts = [...]string{
	time.RFC3339,             // 2025-07-06T06:00:00+01:00
	"2006-01-02 15:04 -0700", // full datetime + offset
	"2006-01-02 15 -0700",    // date + hour + offset
	"2006-01-02 -0700",       // date + offset
}

// timeBoundZonelessLayouts carry no zone: the bound is compared against the
// wall clock of each log line, whatever the line's offset.
var timeBoundZonelessLayouts = [...]string{
	"2006-01-02 15:04", // full datetime
	"2006-01-02 15",    // date + hour
	"2006-01-02",       // just date
}

// ParseTimeBound parses a startTime/endTime bound. It is THE parser for both
// surfaces - the TOML keys and the --startTime/--endTime flags - so a value
// accepted by one is accepted by the other (they used to accept disjoint
// syntaxes: RFC3339 only in TOML, the short forms only on the command line).
//
// hasOffset reports whether the bound carried an explicit zone offset
// (URGENT-09): such a bound is compared as a true instant, a zone-less one
// wall-clock / zone-agnostically against each log line.
func ParseTimeBound(input string) (t time.Time, hasOffset bool, err error) {
	for _, layout := range timeBoundOffsetLayouts {
		if parsed, perr := time.Parse(layout, input); perr == nil {
			return parsed, true, nil
		}
	}
	for _, layout := range timeBoundZonelessLayouts {
		if parsed, perr := time.Parse(layout, input); perr == nil {
			return parsed, false, nil
		}
	}
	return time.Time{}, false, fmt.Errorf("invalid time format %q (want %s)", input, TimeBoundFormats)
}

// LiveWarnings returns one line per [live.<name>] key that is accepted for
// parity with the static trie key surface but has NO effect in live mode
// (startTime, endTime, cidrRanges). They are warnings, not errors: a config
// that sets them keeps loading, but the operator is told the key does nothing
// instead of assuming a time filter or range report is active. Sorted for
// stable output. The live command logs them at startup.
func (c *Config) LiveWarnings() []string {
	var warnings []string
	for name, stc := range c.LiveTries {
		if stc == nil {
			continue
		}
		for _, key := range stc.ignoredKeys {
			warnings = append(warnings, fmt.Sprintf("[live.%s] %s has no effect in live mode and is ignored (%s)", name, key, ignoredLiveKeyReason[key]))
		}
	}
	sort.Strings(warnings)
	return warnings
}

// ignoredLiveKeys are the sliding-trie keys that are validated but never
// consumed, in the order LiveWarnings lists them per window.
var ignoredLiveKeys = [...]string{"startTime", "endTime", "cidrRanges"}

var ignoredLiveKeyReason = map[string]string{
	"startTime":  "the window is bounded by slidingWindowMaxTime",
	"endTime":    "the window is bounded by slidingWindowMaxTime",
	"cidrRanges": "range counts are a static-mode report",
}
