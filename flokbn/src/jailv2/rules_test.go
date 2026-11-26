package jailv2

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/cidr"
)

// t0 is the time the scenario tests run at.
var t0 = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

func newJail(t testing.TB, overlap int) *Jail {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Overlap = overlap
	j, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func mustParse(t testing.TB, s string) cidr.NumericCIDR {
	t.Helper()
	nc, ok := cidr.Parse(s)
	if !ok {
		t.Fatalf("bad CIDR %q", s)
	}
	return nc
}

func ranges(t testing.TB, list ...string) []cidr.NumericCIDR {
	t.Helper()
	out := make([]cidr.NumericCIDR, len(list))
	for i, s := range list {
		out[i] = mustParse(t, s)
	}
	return out
}

// seed puts records into the jail as they would stand at time now. An entry
// is "cidr stage state": state "ended" is a ban that ran out one minute ago,
// "active" one that started one minute ago.
func seed(t testing.TB, j *Jail, now time.Time, entries ...string) {
	t.Helper()
	for _, e := range entries {
		f := strings.Fields(e)
		if len(f) != 3 {
			t.Fatalf("bad seed entry %q", e)
		}
		nc := mustParse(t, f[0])
		stage := int(f[1][0] - '0')
		start := now.Add(-time.Minute)
		if f[2] == "ended" {
			start = start.Add(-j.cfg.Stages[stage-1])
		}
		j.records = append(j.records, Record{IP: nc.IP, PrefixLen: nc.PrefixLen, Stage: uint8(stage), BanStart: start.UnixNano()})
	}
	before := len(j.records)
	j.normalize()
	if len(j.records) != before {
		t.Fatalf("seed %q is not a tidy jail", entries)
	}
}

// dump lists the records as "cidr stage state" in jail order.
func dump(j *Jail, now time.Time) []string {
	out := []string{}
	for _, r := range j.Records() {
		state := "ended"
		if now.UnixNano() < j.banEnd(&r) {
			state = "active"
		}
		out = append(out, r.CIDR().String()+" "+string(rune('0'+r.Stage))+" "+state)
	}
	return out
}

func wantRecords(t *testing.T, j *Jail, now time.Time, want ...string) {
	t.Helper()
	if got := dump(j, now); !slices.Equal(got, want) {
		t.Errorf("records:\n got  %q\n want %q", got, want)
	}
}

// TestRules walks through every row of the rule table with the default
// threshold of 50%.
func TestRules(t *testing.T) {
	tests := []struct {
		name     string
		overlap  int
		seed     []string
		detected []string
		want     []string
		ignored  int
	}{
		{
			name:     "first offence",
			detected: []string{"10.0.0.0/24"},
			want:     []string{"10.0.0.0/24 1 active"},
		},
		{
			name:     "same range, ban active: nothing",
			seed:     []string{"10.0.0.0/24 2 active"},
			detected: []string{"10.0.0.0/24"},
			want:     []string{"10.0.0.0/24 2 active"},
			ignored:  1,
		},
		{
			name:     "same range, ban ended: next stage",
			seed:     []string{"10.0.0.0/24 2 ended"},
			detected: []string{"10.0.0.0/24"},
			want:     []string{"10.0.0.0/24 3 active"},
		},
		{
			name:     "last stage repeats",
			seed:     []string{"10.0.0.0/24 5 ended"},
			detected: []string{"10.0.0.0/24"},
			want:     []string{"10.0.0.0/24 5 active"},
		},
		{
			name:     "inside an active ban: nothing",
			seed:     []string{"10.0.0.0/16 2 active"},
			detected: []string{"10.0.7.0/24"},
			want:     []string{"10.0.0.0/16 2 active"},
			ignored:  1,
		},
		{
			name:     "inside an active ban, own ended record of a higher stage: still nothing",
			seed:     []string{"10.0.0.0/16 1 active", "10.0.5.5/32 4 ended"},
			detected: []string{"10.0.5.5/32"},
			want:     []string{"10.0.0.0/16 1 active", "10.0.5.5/32 4 ended"},
			ignored:  1,
		},
		{
			name:     "every address banned by two active halves: nothing",
			seed:     []string{"10.0.0.0/25 1 active", "10.0.0.128/25 3 active"},
			detected: []string{"10.0.0.0/24"},
			want:     []string{"10.0.0.0/25 1 active", "10.0.0.128/25 3 active"},
			ignored:  1,
		},
		{
			name:     "half of an ended range: the whole range again, next stage",
			seed:     []string{"10.0.0.0/16 3 ended"},
			detected: []string{"10.0.128.0/17"},
			want:     []string{"10.0.0.0/16 4 active"},
		},
		{
			name:     "single address in an ended range: only the address, one stage up",
			seed:     []string{"10.0.0.0/16 3 ended"},
			detected: []string{"10.0.5.5/32"},
			want:     []string{"10.0.0.0/16 3 ended", "10.0.5.5/32 4 active"},
		},
		{
			name:     "a quarter of an ended range is below 50%",
			seed:     []string{"10.0.0.0/16 3 ended"},
			detected: []string{"10.0.64.0/18"},
			want:     []string{"10.0.0.0/16 3 ended", "10.0.64.0/18 4 active"},
		},
		{
			name:     "a quarter of an ended range reaches a threshold of 25%",
			overlap:  25,
			seed:     []string{"10.0.0.0/16 3 ended"},
			detected: []string{"10.0.64.0/18"},
			want:     []string{"10.0.0.0/16 4 active"},
		},
		{
			name:     "around an ended half: joined, one stage up",
			seed:     []string{"10.0.0.0/25 2 ended"},
			detected: []string{"10.0.0.0/24"},
			want:     []string{"10.0.0.0/24 3 active"},
		},
		{
			name:     "around an ended address: stage 1, the address keeps its record",
			seed:     []string{"10.0.5.5/32 4 ended"},
			detected: []string{"10.0.0.0/16"},
			want:     []string{"10.0.0.0/16 1 active", "10.0.5.5/32 4 ended"},
		},
		{
			name:     "around several ended ranges: their sizes add up",
			seed:     []string{"10.0.0.0/26 2 ended", "10.0.0.128/26 3 ended"},
			detected: []string{"10.0.0.0/24"},
			// Half of the /24 reached stage 2, a quarter stage 3.
			want: []string{"10.0.0.0/24 3 active"},
		},
		{
			name:     "nested records inside count once",
			seed:     []string{"10.0.0.0/25 2 ended", "10.0.0.0/26 4 ended"},
			detected: []string{"10.0.0.0/24"},
			want:     []string{"10.0.0.0/24 3 active", "10.0.0.0/26 4 ended"},
		},
		{
			name:     "nested records inside count once, just below the threshold",
			overlap:  30,
			seed:     []string{"10.0.0.0/27 2 ended", "10.0.0.0/28 3 ended"},
			detected: []string{"10.0.0.0/25"},
			// A quarter of the /25 has a history; counting the /28 on top of
			// the /27 around it would make it three eighths.
			want: []string{"10.0.0.0/25 1 active", "10.0.0.0/27 2 ended", "10.0.0.0/28 3 ended"},
		},
		{
			name:     "an ignored range does not re-ban the ended range around it",
			seed:     []string{"10.0.0.0/23 1 ended", "10.0.0.0/25 2 active", "10.0.0.128/25 2 active"},
			detected: []string{"10.0.0.0/24"},
			want:     []string{"10.0.0.0/23 1 ended", "10.0.0.0/25 2 active", "10.0.0.128/25 2 active"},
			ignored:  1,
		},
		{
			name:     "an ignored range does not re-ban the ended range around the active one",
			overlap:  25,
			seed:     []string{"10.0.0.0/22 1 ended", "10.0.0.0/23 2 active"},
			detected: []string{"10.0.0.0/24"},
			want:     []string{"10.0.0.0/22 1 ended", "10.0.0.0/23 2 active"},
			ignored:  1,
		},
		{
			name:     "around an active half: same stage, the wider range takes over",
			seed:     []string{"10.0.0.0/25 2 active"},
			detected: []string{"10.0.0.0/24"},
			want:     []string{"10.0.0.0/24 2 active"},
		},
		{
			name:     "around an active address of a high stage: stage 1, the address stays banned",
			seed:     []string{"10.0.5.5/32 4 active"},
			detected: []string{"10.0.0.0/16"},
			want:     []string{"10.0.0.0/16 1 active", "10.0.5.5/32 4 active"},
		},
		{
			name:     "old and new both banned: the new range has the deeper history and stays nested",
			seed:     []string{"10.0.0.0/16 1 ended", "10.0.0.0/18 4 ended"},
			detected: []string{"10.0.0.0/17"},
			want:     []string{"10.0.0.0/16 2 active", "10.0.0.0/17 5 active"},
		},
		{
			name:     "threshold 100%: only the same range is the same offender",
			overlap:  100,
			seed:     []string{"10.0.0.0/25 2 ended", "10.1.0.0/24 2 ended"},
			detected: []string{"10.0.0.0/24", "10.1.0.0/24"},
			want:     []string{"10.0.0.0/24 1 active", "10.0.0.0/25 2 ended", "10.1.0.0/24 3 active"},
		},
		{
			name:     "the whole address space",
			seed:     []string{"0.0.0.0/1 2 ended"},
			detected: []string{"0.0.0.0/0"},
			want:     []string{"0.0.0.0/0 3 active"},
		},
		{
			name:     "half of the whole address space",
			seed:     []string{"0.0.0.0/0 1 ended"},
			detected: []string{"128.0.0.0/1"},
			want:     []string{"0.0.0.0/0 2 active"},
		},
		{
			name:     "nested and repeated ranges in one round are judged each on its own",
			seed:     []string{"10.0.5.5/32 4 ended"},
			detected: []string{"10.0.5.5/32", "10.0.0.0/16", "10.0.5.5/32"},
			want:     []string{"10.0.0.0/16 1 active", "10.0.5.5/32 5 active"},
		},
		{
			name:     "two ranges of one round re-ban the same old range",
			seed:     []string{"10.0.0.0/16 3 ended"},
			detected: []string{"10.0.0.0/17", "10.0.128.0/17"},
			want:     []string{"10.0.0.0/16 4 active"},
		},
		{
			name:     "host bits are ignored",
			detected: []string{"10.0.0.77/24"},
			want:     []string{"10.0.0.0/24 1 active"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			overlap := tc.overlap
			if overlap == 0 {
				overlap = 50
			}
			j := newJail(t, overlap)
			seed(t, j, t0, tc.seed...)
			detected := make([]cidr.NumericCIDR, len(tc.detected))
			for i, s := range tc.detected {
				nc := mustParse(t, s)
				if s == "10.0.0.77/24" {
					nc.IP |= 77 // cidr.Parse masks the host bits; put them back
				}
				detected[i] = nc
			}
			out := j.Update(t0, detected)
			wantRecords(t, j, t0, tc.want...)
			if out.Ignored != tc.ignored {
				t.Errorf("Ignored = %d, want %d", out.Ignored, tc.ignored)
			}
		})
	}
}

// TestLadder follows one range through all stages. A detection during a ban
// changes nothing; one after it moves the range up.
func TestLadder(t *testing.T) {
	j := newJail(t, 50)
	q := ranges(t, "192.0.2.0/24")
	now := t0
	for stage, d := range j.cfg.Stages {
		out := j.Update(now, q)
		if stage == 0 && out.Started != 1 || stage > 0 && out.Repeated != 1 {
			t.Fatalf("stage %d: outcome %+v", stage+1, out)
		}
		wantRecords(t, j, now, "192.0.2.0/24 "+string(rune('1'+stage))+" active")

		// Still banned one second before the end, with the start untouched.
		start := j.Records()[0].BanStart
		if out := j.Update(now.Add(d-time.Second), q); out.Ignored != 1 || out.Changed() {
			t.Fatalf("stage %d: detection during the ban: %+v", stage+1, out)
		}
		if j.Records()[0].BanStart != start {
			t.Fatalf("stage %d: detection during the ban moved the ban start", stage+1)
		}
		now = now.Add(d)
		if len(j.Active(now)) != 0 || len(j.BanList(now)) != 0 {
			t.Fatalf("stage %d: still active at the end of its duration", stage+1)
		}
	}
	// The last stage repeats.
	j.Update(now, q)
	wantRecords(t, j, now, "192.0.2.0/24 5 active")
}

// TestShapeJitter: the same offender is detected as a /24, a /23 and a /25 in
// turn. The stage follows it instead of restarting, and no detection bans
// more than twice its own size.
func TestShapeJitter(t *testing.T) {
	j := newJail(t, 50)
	now := t0

	j.Update(now, ranges(t, "10.0.0.0/24"))
	wantRecords(t, j, now, "10.0.0.0/24 1 active")

	now = now.Add(time.Minute)
	j.Update(now, ranges(t, "10.0.0.0/23"))
	wantRecords(t, j, now, "10.0.0.0/23 1 active")

	now = now.Add(time.Minute)
	if out := j.Update(now, ranges(t, "10.0.0.0/25")); out.Ignored != 1 {
		t.Fatalf("a range inside the active /23 was not ignored: %+v", out)
	}

	now = now.Add(20 * time.Minute) // the /23 ban has ended
	j.Update(now, ranges(t, "10.0.0.0/25"))
	wantRecords(t, j, now, "10.0.0.0/23 1 ended", "10.0.0.0/25 2 active")

	now = now.Add(5 * time.Hour) // the /25 ban has ended
	j.Update(now, ranges(t, "10.0.0.0/24"))
	wantRecords(t, j, now, "10.0.0.0/23 2 active", "10.0.0.0/24 3 active")
}

// TestHeartbeat: a round with nothing detected changes nothing until a record
// passes its retention, and a ban that ran out is remembered until then.
func TestHeartbeat(t *testing.T) {
	j := newJail(t, 50)
	q := ranges(t, "10.0.0.0/24")
	j.Update(t0, q) // stage 1, ends after 10 minutes

	end := t0.Add(10 * time.Minute)
	for _, at := range []time.Time{t0.Add(time.Minute), end, end.Add(180 * 24 * time.Hour)} {
		if out := j.Update(at, nil); out.Changed() {
			t.Fatalf("heartbeat at %s changed the jail: %+v", at, out)
		}
	}
	if got := len(j.Active(end)); got != 0 {
		t.Fatalf("%d active bans at the end of the ban", got)
	}

	// Remembered on the last day of the retention: a repeat.
	repeat := newJail(t, 50)
	repeat.Update(t0, q)
	repeat.Update(end.Add(180*24*time.Hour), q)
	wantRecords(t, repeat, end.Add(180*24*time.Hour), "10.0.0.0/24 2 active")

	// Forgotten right after it.
	out := j.Update(end.Add(180*24*time.Hour+time.Nanosecond), nil)
	if out.Pruned != 1 || !out.Changed() || j.Len() != 0 {
		t.Fatalf("record not pruned after its retention: %+v, %d records", out, j.Len())
	}
	j.Update(end.Add(181*24*time.Hour), q)
	wantRecords(t, j, end.Add(181*24*time.Hour), "10.0.0.0/24 1 active")
}

// TestActiveBanIsNeverShortened: a record taken over by a wider one is only
// dropped when the wider ban lasts at least as long.
func TestActiveBanIsNeverShortened(t *testing.T) {
	j := newJail(t, 50)
	// A stage 3 ban on one half, far from over, and an ended stage 1 ban on
	// the /24 around it.
	seed(t, j, t0, "10.0.0.0/24 1 ended", "10.0.0.0/25 3 active")
	// The other half re-bans the /24 at stage 2 (4 hours).
	j.Update(t0, ranges(t, "10.0.0.128/25"))
	wantRecords(t, j, t0, "10.0.0.0/24 2 active", "10.0.0.0/25 3 active")

	after := t0.Add(5 * time.Hour)
	if got := j.BanList(after); !slices.Equal(got, []string{"10.0.0.0/25"}) {
		t.Errorf("ban list after the /24 ban ended = %q, want the stage 3 half", got)
	}
}

func TestBanListActiveAndStageCounts(t *testing.T) {
	j := newJail(t, 50)
	seed(t, j, t0,
		"10.0.0.0/25 1 active",   // two halves ...
		"10.0.0.128/25 2 active", // ... of one /24
		"10.0.0.200/32 4 active", // nested in the second half
		"10.9.0.0/16 3 ended",
		"192.0.2.1/32 5 active",
	)

	if got, want := j.BanList(t0), []string{"10.0.0.0/24", "192.0.2.1/32"}; !slices.Equal(got, want) {
		t.Errorf("BanList = %q, want %q", got, want)
	}

	active := j.Active(t0)
	var got []string
	for _, b := range active {
		got = append(got, b.CIDR.String())
		if want := b.Start.Add(j.cfg.Stages[b.Stage-1]); !b.End.Equal(want) {
			t.Errorf("%s: End = %s, want %s", b.CIDR, b.End, want)
		}
	}
	if want := []string{"10.0.0.0/25", "10.0.0.128/25", "10.0.0.200/32", "192.0.2.1/32"}; !slices.Equal(got, want) {
		t.Errorf("Active = %q, want %q", got, want)
	}

	counts := j.StageCounts(t0)
	wantCounts := [][2]int{{1, 1}, {1, 1}, {1, 0}, {1, 1}, {1, 1}} // records, active
	for i, c := range counts {
		if c.Stage != i+1 || c.Duration != j.cfg.Stages[i] || c.Records != wantCounts[i][0] || c.Active != wantCounts[i][1] {
			t.Errorf("StageCounts[%d] = %+v, want records/active %v", i, c, wantCounts[i])
		}
	}

	if got := j.BanList(t0.Add(365 * 24 * time.Hour)); len(got) != 0 {
		t.Errorf("BanList a year later = %q, want none", got)
	}
}

// TestPublishThroughWhitelist: BanList feeds cidr.ComposeBanLists, the place
// where the whitelist is subtracted before anything is published.
func TestPublishThroughWhitelist(t *testing.T) {
	j := newJail(t, 50)
	j.Update(t0, ranges(t, "10.0.0.0/24", "192.0.2.0/24"))

	bans, blacklist := cidr.ComposeBanLists(j.BanList(t0), []string{"203.0.113.7/32"}, []string{"10.0.0.0/25", "192.0.2.0/24"})
	if want := []string{"10.0.0.128/25"}; !slices.Equal(bans, want) {
		t.Errorf("published bans = %q, want %q", bans, want)
	}
	if want := []string{"203.0.113.7/32"}; !slices.Equal(blacklist, want) {
		t.Errorf("published blacklist = %q, want %q", blacklist, want)
	}
}

func TestUpdateCIDRs(t *testing.T) {
	j := newJail(t, 50)
	out, err := j.UpdateCIDRs(t0, []string{"10.0.0.0/24", "not a cidr", "2001:db8::/32", "::ffff:10.1.0.0/120", "10.2.0.77/24"})
	if err == nil {
		t.Fatal("no error for the entries that are not IPv4 CIDRs")
	}
	for _, bad := range []string{"not a cidr", "2001:db8::/32", "::ffff:10.1.0.0/120"} {
		if !strings.Contains(err.Error(), bad) {
			t.Errorf("error %q does not name %q", err, bad)
		}
	}
	if out.Started != 2 {
		t.Errorf("Started = %d, want 2", out.Started)
	}
	wantRecords(t, j, t0, "10.0.0.0/24 1 active", "10.2.0.0/24 1 active")
}

func TestConfigValidation(t *testing.T) {
	good := DefaultConfig()
	if _, err := New(good); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
	bad := map[string]func(*Config){
		"no stages":              func(c *Config) { c.Stages = nil },
		"too many stages":        func(c *Config) { c.Stages = make([]time.Duration, MaxStages+1) },
		"zero duration":          func(c *Config) { c.Stages = []time.Duration{0} },
		"shorter later stage":    func(c *Config) { c.Stages = []time.Duration{time.Hour, time.Minute} },
		"overlap 0":              func(c *Config) { c.Overlap = 0 },
		"overlap 101":            func(c *Config) { c.Overlap = 101 },
		"negative retention":     func(c *Config) { c.Retention = -time.Second },
		"negative stage value":   func(c *Config) { c.Stages = []time.Duration{-time.Minute} },
		"stage of a century":     func(c *Config) { c.Stages = []time.Duration{100 * 365 * 24 * time.Hour} },
		"retention of a century": func(c *Config) { c.Retention = 100 * 365 * 24 * time.Hour },
	}
	for name, change := range bad {
		cfg := DefaultConfig()
		change(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
