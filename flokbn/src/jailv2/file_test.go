package jailv2

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/jail"
)

func TestEncodeFormat(t *testing.T) {
	j := newJail(t, 50)
	j.Update(t0, ranges(t, "192.0.2.7/32", "10.0.0.0/16"))
	j.Update(t0.Add(11*time.Minute+500*time.Millisecond), ranges(t, "10.0.0.0/16"))

	want := `{"version":2,"records":[
{"cidr":"10.0.0.0/16","stage":2,"banStart":"2026-11-26T12:11:00.5Z"},
{"cidr":"192.0.2.7/32","stage":1,"banStart":"2026-11-26T12:00:00Z"}
]}
`
	if got := string(j.Encode()); got != want {
		t.Errorf("Encode:\n got  %s\n want %s", got, want)
	}

	back, err := Decode(j.Encode(), DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(back.Records(), j.Records()) {
		t.Errorf("decoded records %v, want %v", back.Records(), j.Records())
	}

	empty := newJail(t, 50)
	if got, want := string(empty.Encode()), "{\"version\":2,\"records\":[\n]}\n"; got != want {
		t.Errorf("Encode of an empty jail = %q, want %q", got, want)
	}
	if back, err := Decode(empty.Encode(), DefaultConfig()); err != nil || back.Len() != 0 {
		t.Errorf("Decode of an empty jail: %d records, err %v", back.Len(), err)
	}
}

func TestDecodeEmptyInput(t *testing.T) {
	for _, data := range []string{"", " \n\t"} {
		j, err := Decode([]byte(data), DefaultConfig())
		if err != nil || j.Len() != 0 {
			t.Errorf("Decode(%q): %v, err %v; want an empty jail", data, j, err)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	tests := map[string]string{
		"invalid JSON":           `{invalid`,
		"null":                   `null`,
		"empty object":           `{}`,
		"a list":                 `[]`,
		"previous format, null":  `{"Cells":null}`,
		"previous format, empty": `{"Cells":[],"AllCidrs":[]}`,
		"unknown version":        `{"version":3,"records":[]}`,
		"both formats":           `{"version":2,"records":[],"Cells":[{"Prisoners":[]}]}`,
		"not a CIDR":             `{"version":2,"records":[{"cidr":"10.0.0.1","stage":1,"banStart":"2026-01-01T00:00:00Z"}]}`,
		"IPv6":                   `{"version":2,"records":[{"cidr":"2001:db8::/32","stage":1,"banStart":"2026-01-01T00:00:00Z"}]}`,
		"IPv4-mapped IPv6":       `{"version":2,"records":[{"cidr":"::ffff:10.0.0.0/120","stage":1,"banStart":"2026-01-01T00:00:00Z"}]}`,
		"stage 0":                `{"version":2,"records":[{"cidr":"10.0.0.0/24","stage":0,"banStart":"2026-01-01T00:00:00Z"}]}`,
		"stage 6":                `{"version":2,"records":[{"cidr":"10.0.0.0/24","stage":6,"banStart":"2026-01-01T00:00:00Z"}]}`,
		"bad time":               `{"version":2,"records":[{"cidr":"10.0.0.0/24","stage":1,"banStart":"yesterday"}]}`,
		"previous format, IPv6":  `{"Cells":[{"Prisoners":[{"Cidr":"2001:db8::/32","BanStart":"2026-01-01T00:00:00Z","BanActive":true}]}]}`,
	}
	for name, data := range tests {
		if j, err := Decode([]byte(data), DefaultConfig()); err == nil {
			t.Errorf("%s: accepted as a jail with %d records", name, j.Len())
		}
	}
}

// TestDecodeNormalizes: a file edited by hand may list a range twice or keep
// records a wider one covers. Decode brings it into the form the jail keeps.
func TestDecodeNormalizes(t *testing.T) {
	data := `{"version":2,"records":[
{"cidr":"10.0.1.0/24","stage":1,"banStart":"2026-11-26T11:59:00Z"},
{"cidr":"10.0.0.0/16","stage":2,"banStart":"2026-11-26T11:59:00Z"},
{"cidr":"10.0.9.9/32","stage":4,"banStart":"2026-11-26T11:59:00Z"},
{"cidr":"192.0.2.77/24","stage":1,"banStart":"2026-11-26T11:59:00Z"},
{"cidr":"192.0.2.0/24","stage":3,"banStart":"2026-11-01T00:00:00Z"}
]}`
	j, err := Decode([]byte(data), DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	wantRecords(t, j, t0,
		"10.0.0.0/16 2 active", // covers the /24 at stage 1
		"10.0.9.9/32 4 active", // higher stage: stays nested
		"192.0.2.0/24 3 ended", // listed twice: the higher stage is kept
	)
}

// TestDecodePreviousFormat takes a file written by package jail and requires
// the same ranges, stages, ban starts and active bans.
func TestDecodePreviousFormat(t *testing.T) {
	now := time.Now()
	old := jail.NewJail()
	type entry struct {
		cidr  string
		cell  int
		start time.Time
	}
	entries := []entry{
		{"10.0.0.0/16", 0, now.Add(-5 * time.Minute)},         // stage 1, active
		{"10.9.0.0/24", 0, now.Add(-15 * time.Minute)},        // stage 1, ended
		{"172.16.0.0/12", 1, now.Add(-time.Hour)},             // stage 2, active
		{"192.0.2.7/32", 2, now.Add(-8 * 24 * time.Hour)},     // stage 3, ended
		{"198.51.100.0/24", 3, now.Add(-24 * time.Hour)},      // stage 4, active
		{"203.0.113.0/25", 4, now.Add(-100 * 24 * time.Hour)}, // stage 5, active
	}
	for _, e := range entries {
		old.Cells[e.cell].Prisoners = append(old.Cells[e.cell].Prisoners,
			jail.Prisoner{CIDR: e.cidr, BanStart: e.start, BanActive: true})
		old.AllCIDRs = append(old.AllCIDRs, e.cidr)
	}
	old.UpdateBanActiveStatus()
	data, err := jail.JailToJSON(old)
	if err != nil {
		t.Fatal(err)
	}

	j, err := Decode([]byte(data), DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if j.Len() != len(entries) {
		t.Fatalf("%d records, want %d", j.Len(), len(entries))
	}
	for _, e := range entries {
		nc := mustParse(t, e.cidr)
		i := j.lowerBound(nc.IP, nc.PrefixLen)
		if i == j.Len() || j.records[i].CIDR() != nc {
			t.Errorf("%s is missing", e.cidr)
			continue
		}
		if r := j.records[i]; int(r.Stage) != e.cell+1 || r.BanStart != e.start.UnixNano() {
			t.Errorf("%s: stage %d, ban start %s; want stage %d, %s", e.cidr, r.Stage, time.Unix(0, r.BanStart), e.cell+1, e.start)
		}
	}

	wantActive := old.ListActiveBans()
	slices.Sort(wantActive)
	gotActive := j.BanList(now)
	slices.Sort(gotActive)
	if !slices.Equal(gotActive, wantActive) {
		t.Errorf("active bans %q, package jail has %q", gotActive, wantActive)
	}

	// A jail that package jail wrote before anything was banned.
	fresh, err := jail.JailToJSON(jail.NewJail())
	if err != nil {
		t.Fatal(err)
	}
	if j, err := Decode([]byte(fresh), DefaultConfig()); err != nil || j.Len() != 0 {
		t.Errorf("fresh jail of the previous format: %v, err %v", j, err)
	}

	// The next save is in the new format and reads back the same.
	back, err := Decode(j.Encode(), DefaultConfig())
	if err != nil || !slices.Equal(back.Records(), j.Records()) {
		t.Errorf("re-encoded jail differs: err %v", err)
	}
}

// TestDecodePreviousFormatFewerStages: a file with more stages than the
// Config keeps its deepest entries at the last stage.
func TestDecodePreviousFormatFewerStages(t *testing.T) {
	old := jail.NewJail()
	old.Cells[4].Prisoners = append(old.Cells[4].Prisoners, jail.Prisoner{CIDR: "10.0.0.0/24", BanStart: t0})
	data, err := jail.JailToJSON(old)
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Stages = cfg.Stages[:3]
	j, err := Decode([]byte(data), cfg)
	if err != nil {
		t.Fatal(err)
	}
	wantRecords(t, j, t0, "10.0.0.0/24 3 active")
}

// TestDecodeClampsBanStart: a ban start too far from the present for an int64
// of nanoseconds is moved to the nearest one the jail computes with safely. Such an entry
// stays what it was: ended long ago, or active for good.
func TestDecodeClampsBanStart(t *testing.T) {
	data := `{"version":2,"records":[
{"cidr":"10.0.0.0/24","stage":5,"banStart":"0001-01-01T00:00:00Z"},
{"cidr":"10.0.1.0/24","stage":1,"banStart":"9999-12-31T23:59:59Z"}
]}`
	j, err := Decode([]byte(data), DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	wantRecords(t, j, t0, "10.0.0.0/24 5 ended", "10.0.1.0/24 1 active")
	if got := time.Unix(0, j.Records()[0].BanStart).UTC().Year(); got != 1970 {
		t.Errorf("early ban start clamped to year %d, want 1970", got)
	}
	if got := time.Unix(0, j.Records()[1].BanStart).UTC().Year(); got != 2150 {
		t.Errorf("late ban start clamped to year %d, want 2150", got)
	}
	// The early one is past its retention and goes with the next round.
	if out := j.Update(t0, nil); out.Pruned != 1 {
		t.Errorf("Pruned = %d, want 1", out.Pruned)
	}
}

func TestLoadAndSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jail.json")

	// A missing file is an empty jail.
	j, err := Load(path, DefaultConfig())
	if err != nil || j.Len() != 0 {
		t.Fatalf("Load of a missing file: %v, err %v", j, err)
	}

	j.Update(t0, ranges(t, "10.0.0.0/24", "192.0.2.1/32"))
	if err := j.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("saved file: mode %v, err %v; want 0644", info.Mode(), err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("%d files in the directory after Save, want only the jail file", len(entries))
	}

	back, err := Load(path, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(back.Records(), j.Records()) {
		t.Errorf("loaded records %v, want %v", back.Records(), j.Records())
	}

	// An empty file is an empty jail, a damaged one an error that names it.
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if j, err := Load(path, DefaultConfig()); err != nil || j.Len() != 0 {
		t.Errorf("Load of an empty file: %v, err %v", j, err)
	}
	if err := os.WriteFile(path, []byte(`{"version":2,"records":[{"cidr":"x"`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, DefaultConfig()); err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("Load of a damaged file: err %v, want one naming %s", err, path)
	}

	// A path that cannot be read is an error, not an empty jail.
	if _, err := Load(dir, DefaultConfig()); err == nil {
		t.Error("Load of a directory succeeded")
	}
	if _, err := Load(path, Config{}); err == nil {
		t.Error("Load with an invalid config succeeded")
	}
}

func FuzzDecode(f *testing.F) {
	j, _ := New(DefaultConfig())
	j.Update(t0, ranges(f, "10.0.0.0/16", "10.0.5.5/32", "192.0.2.0/24"))
	f.Add(j.Encode())
	old := jail.NewJail()
	old.Fill("192.168.1.0/24")
	old.Fill("10.0.0.0/8")
	legacy, _ := jail.JailToJSON(old)
	f.Add([]byte(legacy))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{invalid`))
	f.Add([]byte(``))
	f.Add([]byte(`{"version":2,"records":[{"cidr":"10.0.0.0/8","stage":5,"banStart":"0001-01-01T00:00:00Z"},{"cidr":"10.0.0.0/8","stage":1,"banStart":"9999-12-31T23:59:59Z"}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := DefaultConfig()
		j, err := Decode(data, cfg)
		if err != nil {
			return
		}
		recs := j.Records()
		for i, r := range recs {
			if r.PrefixLen > 32 || r.IP != r.CIDR().Interval().Start || r.Stage < 1 || int(r.Stage) > len(cfg.Stages) {
				t.Fatalf("invalid record %+v", r)
			}
			if i > 0 && !recs[i-1].before(r.IP, r.PrefixLen) {
				t.Fatalf("records %d and %d out of order", i-1, i)
			}
		}
		// What was accepted survives a save, and the jail works.
		back, err := Decode(j.Encode(), cfg)
		if err != nil || !slices.Equal(back.Records(), recs) {
			t.Fatalf("encode and decode: err %v\n got  %v\n want %v", err, back.Records(), recs)
		}
		j.Update(t0, ranges(t, "10.0.0.0/16", "0.0.0.0/0", "255.255.255.255/32"))
		j.BanList(t0)
	})
}
