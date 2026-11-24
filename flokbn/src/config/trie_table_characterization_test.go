package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
)

// Characterization of how a [static.<name>] and a [live.<name>] table are
// parsed and validated. Both tables accept the same filter and cluster keys,
// so both are driven through the same cases here: every diagnostic, in the
// order it is recorded, every hard error and which one wins, and the parsed
// values. The tests read fields and call methods only (no composite literals
// of the trie types), so they do not depend on how the two types are laid out.

// trieTableKinds are the two tables with the config they need around them to
// load, and the mode that validates them.
var trieTableKinds = []struct {
	name    string
	header  string // table header, the keys under test follow it
	section string // as it appears in diagnostics
	mode    RunMode
}{
	{"static", "[static.t]\n", "static.t", StaticMode},
	{"live", "[live.t]\n", "live.t", LiveMode},
}

// kitchenSinkKeys holds one of every collect-all problem a trie table can
// carry. Nothing in it is a hard error, so LoadConfig succeeds.
const kitchenSinkKeys = `
bogusKey = 1
useragentRegex = "(unclosed"
endpointRegex = "[a-"
clusterArgSets = [[1000, 24, 32, 0.1], "row", [1, 2, "x", 4], [1, 2, 3], [0, 40, 30, 3.5]]
useForJail = [true, "yes", false]
startTime = "not-a-time"
endTime = "also-not"
cidrRanges = ["10.0.0.0/8", "2001:db8::/32", "nope", "10.1.2.3", "::1"]
`

// The diagnostics LoadConfig records for kitchenSinkKeys, in recording order.
// %s is the section; the unknown-key line differs per table and is checked
// separately.
var kitchenSinkParseDiags = []string{
	`[%s] clusterArgSets row 1 must be an array of 4 numbers, got string`,
	`[%s] clusterArgSets row 2 contains a non-numeric value "x" (string)`,
	`[%s] clusterArgSets row 3 requires exactly 4 numeric values (minClusterSize,minDepth,maxDepth,meanSubnetDifference), got 3`,
	`[%s] clusterArgSets row 4: minClusterSize (0) must be a whole number between 1 and 4294967295; minDepth (40) must be a whole number between 0 and 32; meanSubnetDifference (3.5) must be a number between 0 and 2`,
	`[%s] useForJail[1] must be a boolean, got string`,
	`[%s] invalid useragentRegex pattern: error parsing regexp: missing closing ): ` + "`(unclosed`",
	`[%s] invalid endpointRegex pattern: error parsing regexp: missing closing ]: ` + "`[a-`",
	`[%s] IPv6 not supported (IPv4-only tool) in cidrRanges[1]: "2001:db8::/32"`,
	`[%s] invalid cidrRanges[2] "nope": invalid CIDR address: nope`,
	`[%s] IPv6 not supported (IPv4-only tool) in cidrRanges[4]: "::1"`,
}

func TestTrieTable_KitchenSinkParseDiagnostics(t *testing.T) {
	unknownKey := map[string]string{
		"static": `unknown key "bogusKey" in [static.t] trie section (want: cidrRanges, clusterArgSets, endTime, endpointRegex, startTime, useForJail, useragentRegex)`,
		"live":   `unknown key "bogusKey" in [live.t] sliding-trie section (want: cidrRanges, clusterArgSets, endTime, endpointRegex, sleepBetweenIterations, slidingWindowMaxSize, slidingWindowMaxTime, startTime, useForJail, useragentRegex)`,
	}
	for _, kind := range trieTableKinds {
		t.Run(kind.name, func(t *testing.T) {
			cfg, err := loadConfigString(t, kind.header+kitchenSinkKeys)
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			want := []string{unknownKey[kind.name]}
			for _, line := range kitchenSinkParseDiags {
				want = append(want, strings.Replace(line, "%s", kind.section, 1))
			}
			if got := cfg.diags.msgs; !reflect.DeepEqual(got, want) {
				t.Errorf("parse diagnostics differ\n got: %s\nwant: %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
			}
		})
	}
}

// Validate appends its own per-table checks after the parse diagnostics: the
// two unparseable bounds, in that order. The useForJail alignment check stays
// silent because rows were dropped.
func TestTrieTable_KitchenSinkValidateDiagnostics(t *testing.T) {
	for _, kind := range trieTableKinds {
		t.Run(kind.name, func(t *testing.T) {
			cfg, err := loadConfigString(t, kind.header+kitchenSinkKeys)
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			parsed := len(cfg.diags.msgs)
			got := cfg.Validate(kind.mode).msgs
			if len(got) < parsed+2 {
				t.Fatalf("Validate recorded %d lines, want at least %d:\n%s", len(got), parsed+2, strings.Join(got, "\n"))
			}
			if !reflect.DeepEqual(got[:parsed], cfg.diags.msgs) {
				t.Errorf("Validate must start with the parse diagnostics, got:\n%s", strings.Join(got[:parsed], "\n"))
			}
			want := []string{
				`[` + kind.section + `] invalid startTime "not-a-time": want ` + TimeBoundFormats,
				`[` + kind.section + `] invalid endTime "also-not": want ` + TimeBoundFormats,
			}
			if !reflect.DeepEqual(got[parsed:parsed+2], want) {
				t.Errorf("per-table validate diagnostics differ\n got: %s\nwant: %s",
					strings.Join(got[parsed:parsed+2], "\n      "), strings.Join(want, "\n      "))
			}
			for _, line := range got {
				if strings.Contains(line, "useForJail has") {
					t.Errorf("alignment check must stay silent after a dropped row, got: %s", line)
				}
			}
		})
	}
}

// A table with intact rows gets the range and alignment checks from Validate.
func TestTrieTable_RangeAndAlignmentDiagnostics(t *testing.T) {
	const keys = `
clusterArgSets = [[1000, 24, 32, 0.1], [500, 16, 24, 0.2]]
useForJail = [true]
startTime = "2025-06-02"
endTime = "2025-06-01"
`
	for _, kind := range trieTableKinds {
		t.Run(kind.name, func(t *testing.T) {
			cfg, err := loadConfigString(t, kind.header+keys)
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if n := len(cfg.diags.msgs); n != 0 {
				t.Fatalf("parse must record nothing, got %v", cfg.diags.msgs)
			}
			got := cfg.Validate(kind.mode).msgs
			want := []string{
				`[` + kind.section + `] endTime "2025-06-01" is before startTime "2025-06-02": want endTime >= startTime`,
				`[` + kind.section + `] useForJail has 1 entries but clusterArgSets has 2; they must match one-to-one (omit useForJail to apply no jail rules)`,
			}
			if len(got) < 2 || !reflect.DeepEqual(got[:2], want) {
				t.Errorf("validate diagnostics differ\n got: %s\nwant: %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
			}
		})
	}
}

// Every key with the wrong TOML type is a hard LoadConfig error. The keys are
// checked in a fixed order, so with several wrong keys the first one in that
// order is the one reported: the test removes the keys one by one from the
// front and expects the error to move to the next.
func TestTrieTable_HardErrorsAndTheirOrder(t *testing.T) {
	type wrongKey struct{ line, wantErr string }
	common := []wrongKey{
		{`useragentRegex = 1`, `useragentRegex must be a string, got int64`},
		{`endpointRegex = 2`, `endpointRegex must be a string, got int64`},
		{`clusterArgSets = "x"`, `clusterArgSets must be an array of [minClusterSize,minDepth,maxDepth,meanSubnetDifference] rows, got string`},
		{`useForJail = true`, `useForJail must be an array of booleans, got bool`},
		{`startTime = 2025-01-01T00:00:00Z`, `startTime must be a string, got time.Time`},
		{`endTime = 5`, `endTime must be a string, got int64`},
	}
	sliding := []wrongKey{
		{`slidingWindowMaxTime = 3600`, `slidingWindowMaxTime must be a string, got int64`},
		{`slidingWindowMaxSize = "big"`, `slidingWindowMaxSize must be an integer, got string`},
		{`sleepBetweenIterations = "10"`, `sleepBetweenIterations must be an integer, got string`},
	}
	cidrRanges := []wrongKey{
		{`cidrRanges = "10.0.0.0/8"`, `cidrRanges must be an array of strings, got string`},
	}
	order := map[string][]wrongKey{
		"static": append(append([]wrongKey{}, common...), cidrRanges...),
		"live":   append(append(append([]wrongKey{}, common...), sliding...), cidrRanges...),
	}
	prefix := map[string]string{
		"static": `parsing trie config "t": `,
		"live":   `parsing sliding trie config "t": `,
	}
	for _, kind := range trieTableKinds {
		keys := order[kind.name]
		for first := range keys {
			t.Run(kind.name+"/"+strings.Fields(keys[first].line)[0], func(t *testing.T) {
				body := kind.header
				for _, k := range keys[first:] {
					body += k.line + "\n"
				}
				_, err := loadConfigString(t, body)
				want := prefix[kind.name] + keys[first].wantErr
				if err == nil || err.Error() != want {
					t.Errorf("error differs\n got: %v\nwant: %s", err, want)
				}
			})
		}
	}

	// Malformed values that are hard errors rather than diagnostics.
	for _, tc := range []struct{ name, body, wantErr string }{
		{"static cidrRanges element", "[static.t]\ncidrRanges = [\"10.0.0.0/8\", 7]\n",
			`parsing trie config "t": cidrRanges[1] must be a string, got int64`},
		{"live cidrRanges element", "[live.t]\ncidrRanges = [\"10.0.0.0/8\", 7]\n",
			`parsing sliding trie config "t": cidrRanges[1] must be a string, got int64`},
		{"live slidingWindowMaxTime value", "[live.t]\nslidingWindowMaxTime = \"soon\"\n",
			`parsing sliding trie config "t": invalid slidingWindowMaxTime "soon": time: invalid duration "soon"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfigString(t, tc.body)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("error differs\n got: %v\nwant: %s", err, tc.wantErr)
			}
		})
	}
}

// A fully valid table: the same keys give the same parsed values in both
// tables, and the filters they compile behave the same.
func TestTrieTable_ParsedValues(t *testing.T) {
	const keys = `
useragentRegex = "(?i)bot"
endpointRegex = "^/api/"
clusterArgSets = [[1000, 24, 32, 0.1], [500, 16, 24, 0.25]]
useForJail = [true, false]
startTime = "2025-06-01 06:00"
endTime = "2025-06-02T00:00:00+02:00"
cidrRanges = ["10.0.0.0/8", "192.168.1.7"]
`
	wantSets := []ClusterArgSet{
		{MinClusterSize: 1000, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.1},
		{MinClusterSize: 500, MinDepth: 16, MaxDepth: 24, MeanSubnetDifference: 0.25},
	}
	wantStart := time.Date(2025, 6, 1, 6, 0, 0, 0, time.UTC)
	wantEnd := time.Date(2025, 6, 1, 22, 0, 0, 0, time.UTC)
	requests := []struct {
		req  accesslog.Request
		want bool
	}{
		{accesslog.Request{UserAgent: "GoogleBot/2.1", URI: "/api/users"}, true},
		{accesslog.Request{UserAgent: "GoogleBot/2.1", URI: "/home"}, false},
		{accesslog.Request{UserAgent: "Mozilla/5.0", URI: "/api/users"}, false},
		{accesslog.Request{UserAgent: "", URI: "/api/users"}, false},
		{accesslog.Request{UserAgent: "bot", URI: ""}, false},
	}

	t.Run("static", func(t *testing.T) {
		cfg, err := loadConfigString(t, "[static.t]\n"+keys)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if n := cfg.Validate(StaticMode).Len(); n != 0 {
			t.Fatalf("valid table must record nothing, got:\n%s", cfg.Validate(StaticMode).Report())
		}
		tc := cfg.StaticTries["t"]
		if tc.UserAgentRegex != "(?i)bot" || tc.EndpointRegex != "^/api/" {
			t.Errorf("regex strings = %q, %q", tc.UserAgentRegex, tc.EndpointRegex)
		}
		if !reflect.DeepEqual(tc.ClusterArgSets, wantSets) || !reflect.DeepEqual(tc.UseForJail, []bool{true, false}) {
			t.Errorf("cluster sets = %v, useForJail = %v", tc.ClusterArgSets, tc.UseForJail)
		}
		if tc.StartTime == nil || !tc.StartTime.Equal(wantStart) || tc.StartTimeHasOffset {
			t.Errorf("startTime = %v (hasOffset %v), want zone-less %v", tc.StartTime, tc.StartTimeHasOffset, wantStart)
		}
		if tc.EndTime == nil || !tc.EndTime.Equal(wantEnd) || !tc.EndTimeHasOffset {
			t.Errorf("endTime = %v (hasOffset %v), want instant %v", tc.EndTime, tc.EndTimeHasOffset, wantEnd)
		}
		if want := []string{"10.0.0.0/8", "192.168.1.7/32"}; !reflect.DeepEqual(tc.CIDRRanges, want) {
			t.Errorf("cidrRanges = %v, want %v", tc.CIDRRanges, want)
		}
		for _, r := range requests {
			if got := tc.ShouldIncludeRequest(r.req); got != r.want {
				t.Errorf("ShouldIncludeRequest(%q, %q) = %v, want %v", r.req.UserAgent, r.req.URI, got, r.want)
			}
		}
	})

	t.Run("live", func(t *testing.T) {
		cfg, err := loadConfigString(t, "[live.t]\n"+keys+`
slidingWindowMaxTime = "90m"
slidingWindowMaxSize = 5000
sleepBetweenIterations = 3
`)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if n := len(cfg.diags.msgs); n != 0 {
			t.Fatalf("valid table must record nothing at parse, got %v", cfg.diags.msgs)
		}
		stc := cfg.LiveTries["t"]
		if stc.UserAgentRegex != "(?i)bot" || stc.EndpointRegex != "^/api/" {
			t.Errorf("regex strings = %q, %q", stc.UserAgentRegex, stc.EndpointRegex)
		}
		if !reflect.DeepEqual(stc.ClusterArgSets, wantSets) || !reflect.DeepEqual(stc.UseForJail, []bool{true, false}) {
			t.Errorf("cluster sets = %v, useForJail = %v", stc.ClusterArgSets, stc.UseForJail)
		}
		if stc.StartTime == nil || !stc.StartTime.Equal(wantStart) || stc.StartTimeHasOffset {
			t.Errorf("startTime = %v (hasOffset %v), want zone-less %v", stc.StartTime, stc.StartTimeHasOffset, wantStart)
		}
		if stc.EndTime == nil || !stc.EndTime.Equal(wantEnd) || !stc.EndTimeHasOffset {
			t.Errorf("endTime = %v (hasOffset %v), want instant %v", stc.EndTime, stc.EndTimeHasOffset, wantEnd)
		}
		if stc.SlidingWindowMaxTime != 90*time.Minute || stc.SlidingWindowMaxSize != 5000 || stc.SleepBetweenIterations != 3 {
			t.Errorf("sliding params = %v, %d, %d", stc.SlidingWindowMaxTime, stc.SlidingWindowMaxSize, stc.SleepBetweenIterations)
		}
		for _, r := range requests {
			if got := stc.ShouldIncludeRequest(r.req); got != r.want {
				t.Errorf("ShouldIncludeRequest(%q, %q) = %v, want %v", r.req.UserAgent, r.req.URI, got, r.want)
			}
		}
		wantWarnings := []string{
			"[live.t] cidrRanges has no effect in live mode and is ignored (range counts are a static-mode report)",
			"[live.t] endTime has no effect in live mode and is ignored (the window is bounded by slidingWindowMaxTime)",
			"[live.t] startTime has no effect in live mode and is ignored (the window is bounded by slidingWindowMaxTime)",
		}
		if got := cfg.LiveWarnings(); !reflect.DeepEqual(got, wantWarnings) {
			t.Errorf("LiveWarnings = %v, want %v", got, wantWarnings)
		}
	})

	// An omitted sleepBetweenIterations is the shared default; an empty table
	// has no filters and includes every request.
	t.Run("defaults", func(t *testing.T) {
		cfg, err := loadConfigString(t, "[static.s]\n[live.l]\n")
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if got := cfg.LiveTries["l"].SleepBetweenIterations; got != DefaultSleepBetweenIterations {
			t.Errorf("sleepBetweenIterations = %d, want %d", got, DefaultSleepBetweenIterations)
		}
		if !cfg.StaticTries["s"].ShouldIncludeRequest(accesslog.Request{}) || !cfg.LiveTries["l"].ShouldIncludeRequest(accesslog.Request{}) {
			t.Error("a table without filters must include every request")
		}
	})
}

// A dropped clusterArgSets row clears useForJail in both tables, so a
// shortened set list can never be paired with the original jail flags.
func TestTrieTable_DroppedRowClearsUseForJail(t *testing.T) {
	const keys = `
clusterArgSets = [[1000, 24, 32, 0.1], [1, 2, 3]]
useForJail = [true, true]
`
	cfg, err := loadConfigString(t, "[static.t]\n"+keys+"[live.t]\n"+keys)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if tc := cfg.StaticTries["t"]; len(tc.ClusterArgSets) != 1 || tc.UseForJail != nil {
		t.Errorf("static: sets = %v, useForJail = %v, want 1 set and nil", tc.ClusterArgSets, tc.UseForJail)
	}
	if stc := cfg.LiveTries["t"]; len(stc.ClusterArgSets) != 1 || stc.UseForJail != nil {
		t.Errorf("live: sets = %v, useForJail = %v, want 1 set and nil", stc.ClusterArgSets, stc.UseForJail)
	}
}

// The filter/logFormat cross-check records, per mode, one line per filter
// whose field the format lacks, tables first and the [global] lists last.
func TestTrieTable_FilterFieldDiagnosticsOrder(t *testing.T) {
	const filters = `
useragentRegex = "bot"
endpointRegex = "^/api"
startTime = "2025-06-01"
endTime = "2025-06-02"
`
	const global = `
[global]
userAgentWhitelist = "/nonexistent/ua-white.txt"
userAgentBlacklist = "/nonexistent/ua-black.txt"
`
	fieldLines := func(msgs []string) []string {
		var out []string
		for _, m := range msgs {
			if strings.Contains(m, "needs the") || strings.Contains(m, "has no %t field") {
				out = append(out, m)
			}
		}
		return out
	}

	t.Run("static", func(t *testing.T) {
		cfg, err := loadConfigString(t, global+"[static]\nlogFormat = \"%h\"\n[static.t]\n"+filters)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		tail := `of each request, but logFormat "%h" has no `
		want := []string{
			`[static.t] useragentRegex needs the User-Agent ` + tail + `%u field; add %u to logFormat or remove useragentRegex`,
			`[static.t] endpointRegex needs the request URI ` + tail + `%r or %U field; add %r or %U to logFormat or remove endpointRegex`,
			`[static.t] startTime needs the timestamp ` + tail + `%t field; add %t to logFormat or remove startTime`,
			`[static.t] endTime needs the timestamp ` + tail + `%t field; add %t to logFormat or remove endTime`,
			`[global] userAgentWhitelist needs the User-Agent ` + tail + `%u field; add %u to logFormat or remove userAgentWhitelist`,
			`[global] userAgentBlacklist needs the User-Agent ` + tail + `%u field; add %u to logFormat or remove userAgentBlacklist`,
		}
		if got := fieldLines(cfg.Validate(StaticMode).msgs); !reflect.DeepEqual(got, want) {
			t.Errorf("static filter-field diagnostics differ\n got: %s\nwant: %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
		}
	})

	t.Run("live", func(t *testing.T) {
		cfg, err := loadConfigString(t, global+"[live]\nlogFormat = \"%h\"\n[live.t]\n"+filters)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		tail := `of each request, but [live] logFormat "%h" has no `
		want := []string{
			`[live] logFormat "%h" has no %t field; live mode needs the timestamp of each request for its sliding windows - add %t to logFormat`,
			`[live.t] useragentRegex needs the User-Agent ` + tail + `%u field; add %u to logFormat or remove useragentRegex`,
			`[live.t] endpointRegex needs the request URI ` + tail + `%r or %U field; add %r or %U to logFormat or remove endpointRegex`,
			`[global] userAgentWhitelist needs the User-Agent ` + tail + `%u field; add %u to logFormat or remove userAgentWhitelist`,
			`[global] userAgentBlacklist needs the User-Agent ` + tail + `%u field; add %u to logFormat or remove userAgentBlacklist`,
		}
		if got := fieldLines(cfg.Validate(LiveMode).msgs); !reflect.DeepEqual(got, want) {
			t.Errorf("live filter-field diagnostics differ\n got: %s\nwant: %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
		}
	})

	// A format with %u and %r but no %t: static reports only the bounds, live
	// only the missing timestamp.
	t.Run("timestamp only", func(t *testing.T) {
		cfg, err := loadConfigString(t, "[static]\nlogFormat = \"%h %u %r\"\n[static.t]\n"+filters+
			"[live]\nlogFormat = \"%h %u %r\"\n[live.t]\n"+filters)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if got := fieldLines(cfg.Validate(StaticMode).msgs); len(got) != 2 ||
			!strings.HasPrefix(got[0], "[static.t] startTime needs the timestamp") ||
			!strings.HasPrefix(got[1], "[static.t] endTime needs the timestamp") {
			t.Errorf("static: want the two bound lines, got %v", got)
		}
		if got := fieldLines(cfg.Validate(LiveMode).msgs); len(got) != 1 || !strings.HasPrefix(got[0], "[live] logFormat") {
			t.Errorf("live: want only the missing-%%t line, got %v", got)
		}
	})
}

// BenchmarkShouldIncludeRequest measures the per-request filter call of both
// table types: the static pipeline calls it once per request and trie, live
// mode once per request and window.
func BenchmarkShouldIncludeRequest(b *testing.B) {
	const table = `
useragentRegex = "(?i)(bot|crawl|spider|python-requests|curl|wget|nikto|sqlmap|scan|masscan|Mobile)"
endpointRegex = "(?i)(/dataset|/psi|/islandora|/search|/admin|/api)"
`
	cfg := loadBenchConfig(b, "[static.t]\n"+table+"[live.t]\n"+table)
	reqs := generateRequests(4096)
	tc, stc := cfg.StaticTries["t"], cfg.LiveTries["t"]

	b.Run("static", func(b *testing.B) {
		b.ReportAllocs()
		n := 0
		for i := 0; i < b.N; i++ {
			if tc.ShouldIncludeRequest(reqs[i&4095]) {
				n++
			}
		}
		_ = n
	})
	b.Run("live", func(b *testing.B) {
		b.ReportAllocs()
		n := 0
		for i := 0; i < b.N; i++ {
			if stc.ShouldIncludeRequest(reqs[i&4095]) {
				n++
			}
		}
		_ = n
	})
	b.Run("no_filter", func(b *testing.B) {
		b.ReportAllocs()
		tc := loadBenchConfig(b, "[static.t]\n").StaticTries["t"]
		n := 0
		for i := 0; i < b.N; i++ {
			if tc.ShouldIncludeRequest(reqs[i&4095]) {
				n++
			}
		}
		_ = n
	})
}

func loadBenchConfig(b *testing.B, content string) *Config {
	b.Helper()
	path := filepath.Join(b.TempDir(), "cfg.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		b.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		b.Fatal(err)
	}
	return cfg
}
