package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

const liveWindowPrefix = `
[live.w]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 10
clusterArgSets = [[100, 24, 32, 0.1]]
`

// C8: an omitted TOML sleepBetweenIterations meant 0 (no pause) while the
// --sleepBetweenIterations flag defaults to 10. Both surfaces share one default
// now; an explicit 0 is still honored.
func TestSleepBetweenIterationsDefaultMatchesFlag(t *testing.T) {
	cfg, err := loadConfigString(t, liveWindowPrefix)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if DefaultSleepBetweenIterations != 10 {
		t.Errorf("DefaultSleepBetweenIterations = %d, the documented flag default is 10", DefaultSleepBetweenIterations)
	}
	if got := cfg.LiveTries["w"].SleepBetweenIterations; got != DefaultSleepBetweenIterations {
		t.Errorf("omitted sleepBetweenIterations = %d, want the flag default %d", got, DefaultSleepBetweenIterations)
	}

	cfg, err = loadConfigString(t, liveWindowPrefix+"sleepBetweenIterations = 0\n")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.LiveTries["w"].SleepBetweenIterations; got != 0 {
		t.Errorf("explicit sleepBetweenIterations = 0 must be honored, got %d", got)
	}

	cfg, err = loadConfigString(t, liveWindowPrefix+"sleepBetweenIterations = 3\n")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.LiveTries["w"].SleepBetweenIterations; got != 3 {
		t.Errorf("explicit sleepBetweenIterations = 3, got %d", got)
	}
}

// The flags-mode default cluster set has one definition; callers get their own
// copy.
func TestDefaultClusterArgSets(t *testing.T) {
	want := []ClusterArgSet{{MinClusterSize: 1000, MinDepth: 30, MaxDepth: 32, MeanSubnetDifference: 0.2}}
	got := DefaultClusterArgSets()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DefaultClusterArgSets() = %+v, want %+v", got, want)
	}
	got[0].MinClusterSize = 1
	if again := DefaultClusterArgSets(); !reflect.DeepEqual(again, want) {
		t.Errorf("DefaultClusterArgSets must return a fresh slice, got %+v after a caller mutation", again)
	}
	// The default must itself satisfy the shared validator.
	d := want[0]
	if _, err := validateClusterArgValues(float64(d.MinClusterSize), float64(d.MinDepth), float64(d.MaxDepth), d.MeanSubnetDifference); err != nil {
		t.Errorf("default cluster set fails validation: %v", err)
	}
}

// [live.<name>] accepts startTime/endTime/cidrRanges but never uses them. The
// config keeps loading; LiveWarnings names each inert key.
func TestLiveWarningsNameIgnoredKeys(t *testing.T) {
	cfg, err := loadConfigString(t, liveWindowPrefix+`
startTime = "2025-01-01T00:00:00Z"
cidrRanges = ["10.0.0.0/8"]

[live.b]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 10
clusterArgSets = [[100, 24, 32, 0.1]]
endTime = "2025-01-02T00:00:00Z"

[live.clean]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 10
clusterArgSets = [[100, 24, 32, 0.1]]
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	warnings := cfg.LiveWarnings()
	if len(warnings) != 3 {
		t.Fatalf("want 3 warnings, got %d: %q", len(warnings), warnings)
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"[live.w] startTime", "[live.w] cidrRanges", "[live.b] endTime"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings should contain %q, got:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "live.clean") {
		t.Errorf("a window without inert keys must not warn, got:\n%s", joined)
	}
	if !reflect.DeepEqual(warnings, cfg.LiveWarnings()) {
		t.Error("LiveWarnings must be deterministic")
	}

	// No live windows, or a hand-built config: no warnings, no panic.
	if w := (&Config{}).LiveWarnings(); len(w) != 0 {
		t.Errorf("empty config should not warn, got %q", w)
	}
}

// C8: TOML bounds accepted RFC3339 only and the flags only the short forms.
// ParseTimeBound is the single parser for both.
func TestParseTimeBound(t *testing.T) {
	tests := []struct {
		input      string
		want       time.Time
		wantOffset bool
		wantErr    bool
	}{
		{input: "2025-07-06T06:00:00Z", want: time.Date(2025, 7, 6, 6, 0, 0, 0, time.UTC), wantOffset: true},
		{input: "2025-07-06T06:00:00+01:00", want: time.Date(2025, 7, 6, 5, 0, 0, 0, time.UTC), wantOffset: true},
		{input: "2025-07-06 06:00 +0100", want: time.Date(2025, 7, 6, 5, 0, 0, 0, time.UTC), wantOffset: true},
		{input: "2025-07-06 06 -0700", want: time.Date(2025, 7, 6, 13, 0, 0, 0, time.UTC), wantOffset: true},
		{input: "2025-07-06 +0200", want: time.Date(2025, 7, 5, 22, 0, 0, 0, time.UTC), wantOffset: true},
		{input: "2025-07-06 06:00", want: time.Date(2025, 7, 6, 6, 0, 0, 0, time.UTC)},
		{input: "2025-07-06 06", want: time.Date(2025, 7, 6, 6, 0, 0, 0, time.UTC)},
		{input: "2025-07-06", want: time.Date(2025, 7, 6, 0, 0, 0, 0, time.UTC)},
		{input: "2025-07-06T06:00:00", wantErr: true}, // RFC3339 needs a zone
		{input: "2025/07/06", wantErr: true},
		{input: "2025-07-06 06:00:00", wantErr: true},
		{input: "2025-13-45", wantErr: true},
		{input: "", wantErr: true},
	}
	for _, tt := range tests {
		got, hasOffset, err := ParseTimeBound(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseTimeBound(%q) = %v, want an error", tt.input, got)
			} else if !strings.Contains(err.Error(), "RFC3339") || !strings.Contains(err.Error(), "YYYY-MM-DD HH:MM") {
				t.Errorf("ParseTimeBound(%q) error should name the accepted formats, got: %v", tt.input, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTimeBound(%q): %v", tt.input, err)
			continue
		}
		if !got.Equal(tt.want) || hasOffset != tt.wantOffset {
			t.Errorf("ParseTimeBound(%q) = (%v, offset=%v), want (%v, offset=%v)", tt.input, got, hasOffset, tt.want, tt.wantOffset)
		}
	}
}

// The TOML keys accept the short forms the flags accept, with the same
// zone-less semantics (hasOffset=false -> wall-clock comparison).
func TestTOMLTimeBoundsAcceptFlagSyntax(t *testing.T) {
	cfg, err := loadConfigString(t, `
[static.t]
startTime = "2025-07-06 06:00"
endTime = "2025-07-07 +0200"
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if d := cfg.Validate(StaticMode); d.HasErrors() {
		t.Fatalf("short-form bounds should validate, got:\n%s", d.Report())
	}
	tc := cfg.StaticTries["t"]
	if tc.StartTime == nil || !tc.StartTime.Equal(time.Date(2025, 7, 6, 6, 0, 0, 0, time.UTC)) || tc.StartTimeHasOffset {
		t.Errorf("startTime = %v (offset=%v), want zone-less 2025-07-06 06:00", tc.StartTime, tc.StartTimeHasOffset)
	}
	if tc.EndTime == nil || !tc.EndTimeHasOffset {
		t.Errorf("endTime = %v (offset=%v), want an offset-bearing bound", tc.EndTime, tc.EndTimeHasOffset)
	}

	// A value neither syntax accepts still fails, and the diagnostic lists both.
	report := loadAndReport(t, "[static.t]\nstartTime = \"yesterday\"\n", StaticMode)
	for _, want := range []string{`[static.t] invalid startTime "yesterday"`, "RFC3339", "YYYY-MM-DD"} {
		if !strings.Contains(report, want) {
			t.Errorf("report should contain %q, got:\n%s", want, report)
		}
	}
}

// A negative sleepBetweenIterations used to pass validation and then behave
// like 0 (the loop takes the largest value across windows, starting from 0), so
// a typo such as -10 silently removed the pause. It is rejected at the barrier,
// naming the window; an explicit 0 stays valid.
func TestNegativeSleepBetweenIterationsRejected(t *testing.T) {
	const want = "sleepBetweenIterations must be >= 0 in [live.w], got -5"

	report := loadAndReport(t, liveWindowPrefix+"sleepBetweenIterations = -5\n", LiveMode)
	if !strings.Contains(report, want) {
		t.Errorf("negative sleepBetweenIterations must be rejected with %q, got:\n%s", want, report)
	}

	for _, ok := range []string{"sleepBetweenIterations = 0\n", "sleepBetweenIterations = 3\n", ""} {
		report := loadAndReport(t, liveWindowPrefix+ok, LiveMode)
		if strings.Contains(report, "sleepBetweenIterations") {
			t.Errorf("%q must stay valid, got:\n%s", ok, report)
		}
	}

	// Flags mode builds the window by hand (--sleepBetweenIterations -5).
	cfg := &Config{
		Global: &GlobalConfig{JailFile: "jail.json", BanFile: "ban.txt"},
		Live:   &LiveConfig{Port: "9000"},
		LiveTries: map[string]*SlidingTrieConfig{"w": {
			SlidingWindowMaxTime:   time.Hour,
			SlidingWindowMaxSize:   10,
			SleepBetweenIterations: -5,
			TrieCommon: TrieCommon{
				ClusterArgSets: DefaultClusterArgSets(),
			},
		}},
	}
	err := cfg.ValidateLive()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("ValidateLive() = %v, want an error containing %q", err, want)
	}
	cfg.LiveTries["w"].SleepBetweenIterations = 0
	if err := cfg.ValidateLive(); err != nil {
		t.Errorf("explicit 0 must stay valid, got %v", err)
	}
}
