package analysis

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/jail"
	"github.com/ChristianF88/flokbn/testutil"
)

func sortedSet(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

// activeBans lists the records of the jail whose ban is running at now.
func activeBans(j *jail.Jail, now time.Time) []string {
	var out []string
	for _, b := range j.Active(now) {
		out = append(out, b.CIDR.String())
	}
	return sortedSet(out)
}

// publishJail returns a jail holding one ban that has run out (stage 1, ten
// minutes, started an hour before now) and one that started at now.
func publishJail(t *testing.T, now time.Time) *jail.Jail {
	t.Helper()
	j, err := jail.Decode([]byte(testutil.JailJSON(
		testutil.JailRecord{CIDR: publishExpiredCIDR, Stage: 1, BanStart: now.Add(-time.Hour)},
		testutil.JailRecord{CIDR: publishActiveCIDR, Stage: 1, BanStart: now},
	)), jail.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return j
}

// TestUpdateBansRound walks one round through every rule of the pipeline: the
// pre-jail whitelist drop, forced bans, bans that ran out, and the
// publish-time whitelist.
func TestUpdateBansRound(t *testing.T) {
	now := time.Now()
	j := publishJail(t, now)

	in := BanInput{
		Now: now,
		Detected: []string{
			"10.1.0.0/16",   // fully inside the whitelisted /8: dropped
			"172.16.0.0/24", // overlaps a whitelisted /32 only: jailed whole
			"192.0.2.0/24",  // untouched by the whitelist
		},
		ForceBan:  []string{"10.2.3.4/32", "192.0.2.200/32", "100.64.1.1/32"},
		Whitelist: []string{"10.0.0.0/8", "172.16.0.7/32"},
		Blacklist: []string{"10.9.9.0/24", "100.64.0.0/10"},
	}
	detected := append([]string{}, in.Detected...)

	got := UpdateBans(j, in)

	if got.WhitelistDropped != 1 {
		t.Errorf("WhitelistDropped = %d, want 1", got.WhitelistDropped)
	}
	// 2 detected ranges survive the pre-jail drop, plus the 3 forced bans.
	if got.Jailed != 5 {
		t.Errorf("Jailed = %d, want 5", got.Jailed)
	}
	if !got.JailChanged {
		t.Error("JailChanged = false after jailing ranges")
	}
	if got.UpdateErr != nil {
		t.Errorf("UpdateErr = %v", got.UpdateErr)
	}

	// The jail holds a record for everything handed to it. The forced /32
	// inside the whitelisted /8 is jailed too (no pre-jail check), and the
	// forced 192.0.2.200/32 keeps its own record inside the detected
	// 192.0.2.0/24.
	wantJail := []string{"10.2.3.4/32", "100.64.1.1/32", "172.16.0.0/24", "192.0.2.0/24", "192.0.2.200/32", publishActiveCIDR}
	if got := activeBans(j, now); !reflect.DeepEqual(got, sortedSet(wantJail)) {
		t.Errorf("active bans in jail = %v, want %v", got, sortedSet(wantJail))
	}
	if len(testutil.JailRecords(t, j.Encode())) != len(wantJail)+1 {
		t.Errorf("%d records in the jail, want the %d active ones and the ended %s", len(testutil.JailRecords(t, j.Encode())), len(wantJail), publishExpiredCIDR)
	}

	// Published: nested bans are listed once and the whitelist is subtracted
	// exactly. The whitelisted forced ban is gone, 172.16.0.0/24 is carved
	// around .7, the ban that ran out is not listed.
	for _, banned := range got.Bans {
		if banned == "10.2.3.4/32" || banned == "172.16.0.0/24" || banned == "192.0.2.200/32" || banned == publishExpiredCIDR {
			t.Errorf("published bans contain %s: %v", banned, got.Bans)
		}
	}
	for _, want := range []string{"192.0.2.0/24", "100.64.1.1/32", publishActiveCIDR, "172.16.0.0/30", "172.16.0.8/29"} {
		found := false
		for _, banned := range got.Bans {
			found = found || banned == want
		}
		if !found {
			t.Errorf("published bans lack %s: %v", want, got.Bans)
		}
	}
	// The manual blacklist loses its whitelisted entry and never enters the jail.
	if !reflect.DeepEqual(got.Blacklist, []string{"100.64.0.0/10"}) {
		t.Errorf("published blacklist = %v, want [100.64.0.0/10]", got.Blacklist)
	}

	if !reflect.DeepEqual(in.Detected, detected) {
		t.Errorf("UpdateBans modified its input: %v", in.Detected)
	}
}

// TestUpdateBansNestedAndNeighbouringRanges: the jail keeps one record per
// detected range, the published list joins what overlaps or touches.
func TestUpdateBansNestedAndNeighbouringRanges(t *testing.T) {
	now := time.Now()
	j, err := jail.New(jail.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	got := UpdateBans(j, BanInput{Now: now, Detected: []string{
		"10.0.0.0/25", "10.0.0.128/25", // two halves of a /24
		"10.0.0.7/32",                  // a host inside the first half
		"192.0.2.0/24", "192.0.2.0/24", // the same range from two cluster sets
	}})
	if len(testutil.JailRecords(t, j.Encode())) != 4 {
		t.Errorf("%d records in the jail, want 4 (one per distinct range)", len(testutil.JailRecords(t, j.Encode())))
	}
	if want := []string{"10.0.0.0/24", "192.0.2.0/24"}; !reflect.DeepEqual(got.Bans, want) {
		t.Errorf("published bans = %v, want %v", got.Bans, want)
	}
}

// TestUpdateBansLeavesInputAlone: with no whitelist the detected ranges pass
// through unfiltered, and appending the forced bans must not write into the
// caller's slice.
func TestUpdateBansLeavesInputAlone(t *testing.T) {
	backing := []string{"192.0.2.0/24", "SENTINEL", "SENTINEL"}
	in := BanInput{Now: time.Now(), Detected: backing[:1], ForceBan: []string{"198.51.100.1/32", "198.51.100.2/32"}}

	j, err := jail.New(jail.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	got := UpdateBans(j, in)

	if got.Jailed != 3 {
		t.Errorf("Jailed = %d, want 3", got.Jailed)
	}
	if backing[1] != "SENTINEL" || backing[2] != "SENTINEL" {
		t.Errorf("UpdateBans wrote past the caller's slice: %v", backing)
	}
}

// TestUpdateBansQuietRound: nothing detected. A ban that ran out leaves the
// published list and is counted once; the jail's records do not change, so
// there is nothing to save.
func TestUpdateBansQuietRound(t *testing.T) {
	now := time.Now()
	j := publishJail(t, now)

	first := UpdateBans(j, BanInput{Now: now})
	if first.JailChanged || first.Jailed != 0 {
		t.Errorf("first quiet round: JailChanged=%v Jailed=%d, want false/0", first.JailChanged, first.Jailed)
	}
	if !reflect.DeepEqual(first.Bans, []string{publishActiveCIDR}) {
		t.Errorf("first quiet round bans = %v, want only %s", first.Bans, publishActiveCIDR)
	}

	// Eleven minutes on, the second ban has run out too.
	second := UpdateBans(j, BanInput{Now: now.Add(11 * time.Minute)})
	if second.JailChanged || second.Expired != 1 {
		t.Errorf("round after the ban ran out: JailChanged=%v Expired=%d, want false/1", second.JailChanged, second.Expired)
	}
	if len(second.Bans) != 0 || len(second.Blacklist) != 0 {
		t.Errorf("round after the ban ran out publishes %v and %v, want nothing", second.Bans, second.Blacklist)
	}
	if len(testutil.JailRecords(t, j.Encode())) != 2 {
		t.Errorf("%d records left, want both: an ended ban is remembered", len(testutil.JailRecords(t, j.Encode())))
	}

	third := UpdateBans(j, BanInput{Now: now.Add(12 * time.Minute)})
	if third.JailChanged || third.Expired != 0 {
		t.Errorf("third quiet round reports a change: JailChanged=%v Expired=%d", third.JailChanged, third.Expired)
	}

	// Past the retention the records are forgotten, and that is a change.
	last := UpdateBans(j, BanInput{Now: now.Add(181 * 24 * time.Hour)})
	if !last.JailChanged || last.Pruned != 2 || len(testutil.JailRecords(t, j.Encode())) != 0 {
		t.Errorf("round after the retention: JailChanged=%v Pruned=%d, %d records; want true/2/0", last.JailChanged, last.Pruned, len(testutil.JailRecords(t, j.Encode())))
	}
}
