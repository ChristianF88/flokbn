package analysis

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/jail"
)

func sortedSet(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

func activeBans(j *jail.Jail) []string {
	return sortedSet(j.ListActiveBans())
}

// TestUpdateBansRound walks one round through every rule of the pipeline: the
// pre-jail whitelist drop, forced bans, expiry, and the publish-time whitelist.
func TestUpdateBansRound(t *testing.T) {
	j := jail.NewJail()
	j.Cells[0].Prisoners = []jail.Prisoner{
		{CIDR: publishExpiredCIDR, BanStart: time.Now().Add(-time.Hour), BanActive: true},
		{CIDR: publishActiveCIDR, BanStart: time.Now(), BanActive: true},
	}
	j.AllCIDRs = []string{publishExpiredCIDR, publishActiveCIDR}

	in := BanInput{
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

	got := UpdateBans(&j, in)

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
	if got.Expired != 1 {
		t.Errorf("Expired = %d, want 1 (%s ran out)", got.Expired, publishExpiredCIDR)
	}

	// The jail holds what was handed to it. The forced /32 inside the
	// whitelisted /8 is jailed too (no pre-jail check); the forced
	// 192.0.2.200/32 is covered by the detected 192.0.2.0/24.
	wantJail := []string{"10.2.3.4/32", "100.64.1.1/32", "172.16.0.0/24", "192.0.2.0/24", publishActiveCIDR}
	if got := activeBans(&j); !reflect.DeepEqual(got, sortedSet(wantJail)) {
		t.Errorf("active bans in jail = %v, want %v", got, sortedSet(wantJail))
	}

	// Published: the whitelist is subtracted exactly. The whitelisted forced
	// ban is gone, 172.16.0.0/24 is carved around .7, the expired ban is out.
	for _, banned := range got.Bans {
		if banned == "10.2.3.4/32" || banned == "172.16.0.0/24" || banned == publishExpiredCIDR {
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

// TestUpdateBansLeavesInputAlone: with no whitelist the detected ranges pass
// through unfiltered, and appending the forced bans must not write into the
// caller's slice.
func TestUpdateBansLeavesInputAlone(t *testing.T) {
	backing := []string{"192.0.2.0/24", "SENTINEL", "SENTINEL"}
	in := BanInput{Detected: backing[:1], ForceBan: []string{"198.51.100.1/32", "198.51.100.2/32"}}

	j := jail.NewJail()
	got := UpdateBans(&j, in)

	if got.Jailed != 3 {
		t.Errorf("Jailed = %d, want 3", got.Jailed)
	}
	if backing[1] != "SENTINEL" || backing[2] != "SENTINEL" {
		t.Errorf("UpdateBans wrote past the caller's slice: %v", backing)
	}
}

// TestUpdateBansQuietRound: nothing detected. Bans that ran out are expired
// and reported as a change; a second quiet round changes nothing.
func TestUpdateBansQuietRound(t *testing.T) {
	j := jail.NewJail()
	j.Cells[0].Prisoners = []jail.Prisoner{
		{CIDR: publishExpiredCIDR, BanStart: time.Now().Add(-time.Hour), BanActive: true},
		{CIDR: publishActiveCIDR, BanStart: time.Now(), BanActive: true},
	}
	j.AllCIDRs = []string{publishExpiredCIDR, publishActiveCIDR}

	first := UpdateBans(&j, BanInput{})
	if !first.JailChanged || first.Jailed != 0 || first.Expired != 1 {
		t.Errorf("first quiet round: JailChanged=%v Jailed=%d Expired=%d, want true/0/1", first.JailChanged, first.Jailed, first.Expired)
	}
	if !reflect.DeepEqual(first.Bans, []string{publishActiveCIDR}) {
		t.Errorf("first quiet round bans = %v, want only %s", first.Bans, publishActiveCIDR)
	}

	second := UpdateBans(&j, BanInput{})
	if second.JailChanged || second.Expired != 0 {
		t.Errorf("second quiet round reports a change: JailChanged=%v Expired=%d", second.JailChanged, second.Expired)
	}
	if !reflect.DeepEqual(second.Bans, []string{publishActiveCIDR}) {
		t.Errorf("second quiet round bans = %v, want only %s", second.Bans, publishActiveCIDR)
	}
	if len(second.Blacklist) != 0 {
		t.Errorf("blacklist = %v, want none", second.Blacklist)
	}
}
