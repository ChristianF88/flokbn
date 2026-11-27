package jail

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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
		"unknown version":        `{"version":3,"records":[]}`,
		"both formats":           `{"version":2,"records":[],"Cells":[{"Prisoners":[]}]}`,
		"earlier format":         `{"Cells":[{"Prisoners":[]}]}`,
		"not a CIDR":             `{"version":2,"records":[{"cidr":"10.0.0.1","stage":1,"banStart":"2026-01-01T00:00:00Z"}]}`,
		"IPv6":                   `{"version":2,"records":[{"cidr":"2001:db8::/32","stage":1,"banStart":"2026-01-01T00:00:00Z"}]}`,
		"IPv4-mapped IPv6":       `{"version":2,"records":[{"cidr":"::ffff:10.0.0.0/120","stage":1,"banStart":"2026-01-01T00:00:00Z"}]}`,
		"stage 0":                `{"version":2,"records":[{"cidr":"10.0.0.0/24","stage":0,"banStart":"2026-01-01T00:00:00Z"}]}`,
		"negative stage":         `{"version":2,"records":[{"cidr":"10.0.0.0/24","stage":-1,"banStart":"2026-01-01T00:00:00Z"}]}`,
		"version only":           `{"version":2}`,
		"records null":           `{"version":2,"records":null}`,
		"records not a list":     `{"version":2,"records":{}}`,
		"version as text":        `{"version":"2","records":[]}`,
		"unknown key":            `{"version":2,"records":[],"comment":"x"}`,
		"misspelt records":       `{"version":2,"records":[],"recordz":[{"cidr":"10.0.0.0/24","stage":5,"banStart":"2026-01-01T00:00:00Z"}]}`,
		"key in upper case":      `{"version":2,"RECORDS":[]}`,
		"records twice":          `{"version":2,"records":[{"cidr":"10.0.0.0/24","stage":3,"banStart":"2026-01-01T00:00:00Z"}],"records":[]}`,
		"no banStart":            `{"version":2,"records":[{"cidr":"10.0.0.0/24","stage":3}]}`,
		"misspelt banStart":      `{"version":2,"records":[{"cidr":"10.0.0.0/24","stage":3,"ban_start":"2026-01-01T00:00:00Z"}]}`,
		"banStart null":          `{"version":2,"records":[{"cidr":"10.0.0.0/24","stage":3,"banStart":null}]}`,
		"no stage":               `{"version":2,"records":[{"cidr":"10.0.0.0/24","banStart":"2026-01-01T00:00:00Z"}]}`,
		"no cidr":                `{"version":2,"records":[{"stage":3,"banStart":"2026-01-01T00:00:00Z"}]}`,
		"record null":            `{"version":2,"records":[null]}`,
		"range twice":            `{"version":2,"records":[{"cidr":"10.0.0.0/24","stage":1,"banStart":"2026-11-26T11:59:00Z"},{"cidr":"10.0.0.0/24","stage":3,"banStart":"2026-06-01T00:00:00Z"}]}`,
		"range twice, host bits": `{"version":2,"records":[{"cidr":"10.0.0.0/24","stage":1,"banStart":"2026-11-26T11:59:00Z"},{"cidr":"10.0.0.77/24","stage":1,"banStart":"2026-11-26T11:59:00Z"}]}`,
		"second document":        `{"version":2,"records":[]}{"version":2,"records":[]}`,
		"text after the end":     `{"version":2,"records":[]} x`,
		"bad time":               `{"version":2,"records":[{"cidr":"10.0.0.0/24","stage":1,"banStart":"yesterday"}]}`,
	}
	for name, data := range tests {
		if j, err := Decode([]byte(data), DefaultConfig()); err == nil {
			t.Errorf("%s: accepted as a jail with %d records", name, j.Len())
		}
	}
}

// TestDecodeNormalizes: a file edited by hand may list its records in any
// order, with host bits, nested, and with a stage the Config no longer has.
// Decode keeps every one of them, in the order the jail keeps.
func TestDecodeNormalizes(t *testing.T) {
	data := `{"version":2,"records":[
{"cidr":"192.0.2.77/24","stage":9,"banStart":"2026-11-26T11:59:00Z"},
{"cidr":"10.0.1.0/24","stage":1,"banStart":"2026-11-26T11:59:00Z"},
{"cidr":"10.0.9.9/32","stage":4,"banStart":"2026-11-26T11:59:00Z"},
{"cidr":"10.0.0.0/16","stage":2,"banStart":"2026-11-26T11:59:00Z"}
]}
`
	j, err := Decode([]byte(data), DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	wantRecords(t, j, t0,
		"10.0.0.0/16 2 active",
		"10.0.1.0/24 1 active", // inside the /16 at a lower stage: kept
		"10.0.9.9/32 4 active",
		"192.0.2.0/24 5 active", // stage 9 of 5: the last stage
	)
	// The first heartbeat changes nothing.
	if out := j.Update(t0, nil); out.Changed() || j.Len() != 4 {
		t.Errorf("first round after loading: %+v, %d records", out, j.Len())
	}
}

// TestDecodeEarlierFormat: a jail file of an earlier flokbn version is not
// read. The error says so and what to do, rather than "not a jail file".
func TestDecodeEarlierFormat(t *testing.T) {
	old := `{"Cells":[{"Id":1,"Description":"Stage 1 Ban","BanDuration":600000000000,"Prisoners":[{"Cidr":"10.0.0.0/24","BanStart":"2026-11-26T11:59:00Z","BanActive":true}]}],"AllCidrs":["10.0.0.0/24"]}`
	_, err := Decode([]byte(old), DefaultConfig())
	if err == nil || !strings.Contains(err.Error(), "earlier flokbn version") || !strings.Contains(err.Error(), "delete it") {
		t.Errorf("Decode of an earlier format: err %v, want one that names the earlier version and the way out", err)
	}
}

// TestDecodeSetsTheClock: the jail's time starts at the latest ban start in
// the file. A clock that is behind after a restart does not bring ended bans
// back, and the first round counts the bans that ran out while flokbn was not
// running.
func TestDecodeSetsTheClock(t *testing.T) {
	data := `{"version":2,"records":[
{"cidr":"10.0.0.0/24","stage":1,"banStart":"2026-11-26T11:00:00Z"},
{"cidr":"10.0.1.0/24","stage":1,"banStart":"2026-11-26T11:55:00Z"},
{"cidr":"10.0.2.0/24","stage":2,"banStart":"2026-11-26T11:58:00Z"}
]}`
	j, err := Decode([]byte(data), DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	// The clock was reset to 2001: the jail stays at 11:58, where the first
	// ban has ended and the other two run.
	wrong := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	if got, want := j.BanList(wrong), []string{"10.0.1.0/24", "10.0.2.0/24"}; !slices.Equal(got, want) {
		t.Errorf("ban list with the clock in 2001 = %q, want %q", got, want)
	}
	if out := j.Update(wrong, nil); out.Changed() || out.Ended != 0 {
		t.Errorf("round with the clock in 2001: %+v, want nothing", out)
	}
	// Back at the right time, ten past twelve: the stage 1 ban from 11:55
	// ran out in between.
	if out := j.Update(t0.Add(10*time.Minute), nil); out.Ended != 1 {
		t.Errorf("Ended = %d, want 1", out.Ended)
	}
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
	f.Add([]byte(`{"Cells":[{"Prisoners":[{"Cidr":"192.168.1.0/24","BanStart":"2026-11-26T11:59:00Z","BanActive":true}]}]}`))
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
