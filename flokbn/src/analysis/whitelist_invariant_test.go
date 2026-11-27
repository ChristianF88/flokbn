package analysis

import (
	"math/rand"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/jail"
)

// TestUpdateBansNeverPublishesWhitelistedAddress is the safety invariant of
// the tool on the path every mode publishes through: whatever the jail holds
// and however its rules ban again (a detected range, a wider record around
// it, the records inside it), no whitelisted address is ever in the published
// lists, and every other banned address is. The whitelist changes between
// rounds, as an edited list file would between runs, and the jail goes through
// its file format now and then.
func TestUpdateBansNeverPublishesWhitelistedAddress(t *testing.T) {
	const arena, arenaBits = uint32(10)<<24 | 77<<16, 12 // 10.77.0.0/20: 4096 addresses
	rng := rand.New(rand.NewSource(20261127))
	pick := func(minPrefix int) string {
		prefix := minPrefix + rng.Intn(33-minPrefix)
		ip := arena | uint32(rng.Intn(1<<arenaBits))
		return cidr.NumericCIDR{IP: ip &^ (^uint32(0) >> prefix), PrefixLen: uint8(prefix)}.String()
	}
	list := func(max, minPrefix int) []string {
		out := make([]string, rng.Intn(max+1))
		for i := range out {
			out[i] = pick(minPrefix)
		}
		return out
	}
	steps := []time.Duration{0, time.Minute, 11 * time.Minute, 5 * time.Hour, 8 * 24 * time.Hour, 31 * 24 * time.Hour}

	scripts := 300
	if testing.Short() {
		scripts = 40
	}
	for script := 0; script < scripts; script++ {
		cfg := jail.DefaultConfig()
		cfg.Overlap = []int{50, 50, 25, 100}[script%4]
		j, err := jail.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
		whitelist := list(6, 22)
		for round := 0; round < 14; round++ {
			now = now.Add(steps[rng.Intn(len(steps))])
			if rng.Intn(4) == 0 {
				whitelist = list(6, 22)
			}
			in := BanInput{
				Now:       now,
				Detected:  list(5, 20),
				ForceBan:  list(2, 32),
				Whitelist: whitelist,
				Blacklist: list(3, 22),
			}
			got := UpdateBans(j, in)
			if got.UpdateErr != nil {
				t.Fatalf("script %d round %d: %v", script, round, got.UpdateErr)
			}

			white := cidr.ParseIntervalSet(whitelist)
			banned := cidr.ParseIntervalSet(j.BanList(now))
			black := cidr.ParseIntervalSet(in.Blacklist)
			pubBans := cidr.ParseIntervalSet(got.Bans)
			pubBlack := cidr.ParseIntervalSet(got.Blacklist)
			for a := arena; a < arena+1<<arenaBits; a++ {
				w := white.Contains(a)
				if w && (pubBans.Contains(a) || pubBlack.Contains(a)) {
					t.Fatalf("script %d round %d: whitelisted address %s is published\nwhitelist %v\nbans %v\nblacklist %v",
						script, round, cidr.NumericCIDR{IP: a, PrefixLen: 32}, whitelist, got.Bans, got.Blacklist)
				}
				if !w && (pubBans.Contains(a) != banned.Contains(a) || pubBlack.Contains(a) != black.Contains(a)) {
					t.Fatalf("script %d round %d: address %s: published as banned %v, banned in the jail %v; published as blacklisted %v, blacklisted %v",
						script, round, cidr.NumericCIDR{IP: a, PrefixLen: 32}, pubBans.Contains(a), banned.Contains(a), pubBlack.Contains(a), black.Contains(a))
				}
			}

			if round%5 == 4 {
				if j, err = jail.Decode(j.Encode(), cfg); err != nil {
					t.Fatalf("script %d round %d: reloading the jail: %v", script, round, err)
				}
			}
		}
	}
}
