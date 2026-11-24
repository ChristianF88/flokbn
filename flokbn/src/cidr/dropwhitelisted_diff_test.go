package cidr

import (
	"math/rand"
	"net"
	"testing"
)

// oldDropFullyWhitelisted is a verbatim copy of DropFullyWhitelisted from
// before it moved from *net.IPNet to numeric intervals. It is the oracle of the
// differential tests below.
func oldDropFullyWhitelisted(blacklist, whitelist []string) (kept []string, dropped int) {
	if len(whitelist) == 0 {
		return blacklist, 0
	}

	whitelistNets := make([]*net.IPNet, 0, len(whitelist))
	for _, entry := range whitelist {
		_, wn, err := net.ParseCIDR(entry)
		if err != nil {
			continue // skip invalid entries
		}
		whitelistNets = append(whitelistNets, wn)
	}

	kept = make([]string, 0, len(blacklist))
	for _, bc := range blacklist {
		_, candidateNet, err := net.ParseCIDR(bc)
		if err != nil {
			kept = append(kept, bc) // keep unparseable entries as-is
			continue
		}
		if IsWhitelistedIPNet(candidateNet, whitelistNets) {
			dropped++
			continue
		}
		kept = append(kept, bc)
	}
	return kept, dropped
}

func checkDropFullyWhitelisted(t *testing.T, bl, wl []string) {
	t.Helper()
	wantKept, wantDropped := oldDropFullyWhitelisted(bl, wl)
	gotKept, gotDropped := DropFullyWhitelisted(bl, wl)
	if !eq(wantKept, gotKept) || wantDropped != gotDropped {
		t.Fatalf("MISMATCH\n bl=%v\n wl=%v\n old=%v dropped=%d\n new=%v dropped=%d",
			bl, wl, wantKept, wantDropped, gotKept, gotDropped)
	}
}

func TestDropDiff_EdgeCases(t *testing.T) {
	cases := []struct {
		name      string
		blacklist []string
		whitelist []string
	}{
		{"both-empty", nil, nil},
		{"empty-bl", nil, []string{"10.0.0.0/8"}},
		{"empty-wl", []string{"10.0.0.0/24"}, nil},
		{"exact", []string{"10.0.0.0/24"}, []string{"10.0.0.0/24"}},
		{"wl-bigger", []string{"10.0.0.0/24"}, []string{"10.0.0.0/16"}},
		{"wl-smaller", []string{"10.0.0.0/16"}, []string{"10.0.0.0/24"}},
		{"union-covers-not-single", []string{"10.0.0.0/24"}, []string{"10.0.0.0/25", "10.0.0.128/25"}},
		{"union-covers-three", []string{"10.0.0.0/24"}, []string{"10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/25"}},
		{"second-entry-covers", []string{"10.0.0.0/24"}, []string{"10.0.0.0/25", "10.0.0.0/8"}},
		{"full-space-wl", []string{"10.0.0.0/8", "0.0.0.0/0", "255.255.255.255/32"}, []string{"0.0.0.0/0"}},
		{"full-space-bl", []string{"0.0.0.0/0"}, []string{"10.0.0.0/8"}},
		{"top-of-space", []string{"255.255.255.128/25", "255.255.255.0/24"}, []string{"255.255.255.128/25"}},
		{"non-canonical-bl-covered", []string{"10.0.0.5/24"}, []string{"10.0.0.0/24"}},
		{"non-canonical-wl", []string{"10.0.0.0/24"}, []string{"10.0.0.99/16"}},
		{"host-in-wl", []string{"10.0.0.7/32", "10.0.0.8/32"}, []string{"10.0.0.7/32"}},
		{"invalid-bl-kept", []string{"not-a-cidr", "", "10.0.0.0/24"}, []string{"10.0.0.0/8"}},
		{"invalid-wl-only", []string{"10.0.0.0/24"}, []string{"garbage", "also-bad"}},
		{"ipv6-wl-ignored", []string{"10.0.0.0/24"}, []string{"::/0", "::ffff:10.0.0.0/104"}},
		{"ipv6-bl-kept", []string{"2001:db8::/32", "::ffff:10.0.0.0/120"}, []string{"0.0.0.0/0", "::/0"}},
		{"padded-prefix", []string{"10.0.0.0/024"}, []string{"10.0.0.0/08"}},
		{"dup-bl", []string{"10.0.0.0/24", "10.0.0.0/24", "11.0.0.0/24"}, []string{"10.0.0.0/8"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checkDropFullyWhitelisted(t, c.blacklist, c.whitelist)
		})
	}
}

// Random ranges across the whole address space, alternating with a tight
// window where containment is frequent.
func TestDropDiff_RandomFuzz(t *testing.T) {
	r := rand.New(rand.NewSource(4711))
	iters := 100000
	if testing.Short() {
		iters = 2000
	}
	tight := func() string {
		ip := uint32(10)<<24 | r.Uint32()&0x0000FFFF
		// Host bits are kept on purpose: non-canonical spellings must be
		// masked the same way by both implementations.
		return NumericCIDR{IP: ip, PrefixLen: uint8(16 + r.Intn(17))}.String()
	}
	for iter := 0; iter < iters; iter++ {
		nb := r.Intn(5)
		nw := r.Intn(6)
		var bl, wl []string
		for i := 0; i < nb; i++ {
			if iter%2 == 0 {
				bl = append(bl, tight())
			} else {
				bl = append(bl, randCidrV4(r))
			}
		}
		for i := 0; i < nw; i++ {
			if iter%2 == 0 {
				wl = append(wl, tight())
			} else {
				wl = append(wl, randCidrV4(r))
			}
		}
		checkDropFullyWhitelisted(t, bl, wl)
	}
}
