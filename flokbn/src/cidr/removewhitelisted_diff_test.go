package cidr

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
)

// oldRemoveWhitelisted is a verbatim copy of the pre-change RemoveWhitelisted
// (base cidr.go line 552), using the still-present IsWhitelisted + SubtractMultiple.
func oldRemoveWhitelisted(blacklist []string, whitelist []string) []string {
	if len(whitelist) == 0 {
		return blacklist
	}
	var result []string
	for _, blackCidr := range blacklist {
		if IsWhitelisted(blackCidr, whitelist) {
			continue
		}
		remainingCidrs, err := SubtractMultiple(blackCidr, whitelist)
		if err != nil {
			result = append(result, blackCidr)
		} else {
			result = append(result, remainingCidrs...)
		}
	}
	return result
}

func eq(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// Curated edge cases (IPv4 only).
func TestDiff_EdgeCases(t *testing.T) {
	cases := []struct {
		name      string
		blacklist []string
		whitelist []string
	}{
		{"left-overlap", []string{"10.0.0.0/24"}, []string{"9.255.255.0/23"}},
		{"left-overlap2", []string{"10.0.0.0/16"}, []string{"9.0.0.0/8", "10.0.5.0/24"}},
		{"wl-spans-window-from-left", []string{"10.0.1.0/24"}, []string{"10.0.0.0/22"}},
		{"wl-spans-from-left-partial", []string{"10.0.2.0/23"}, []string{"10.0.0.0/23", "10.0.3.0/32"}},
		{"two-wl-left-clip-merge", []string{"10.0.0.0/22"}, []string{"9.0.0.0/8", "10.0.0.128/25", "10.0.1.0/24"}},
		{"adjacent-after-clip", []string{"10.0.0.0/22"}, []string{"10.0.0.0/24", "10.0.1.0/24"}},
		{"full-space-bl", []string{"0.0.0.0/0"}, []string{"10.0.0.0/8"}},
		{"full-space-wl", []string{"10.0.0.0/8"}, []string{"0.0.0.0/0"}},
		{"tail-0xFFFF", []string{"255.255.255.0/24"}, []string{"255.255.255.128/25"}},
		{"tail-to-top", []string{"200.0.0.0/8"}, []string{"200.128.0.0/9", "255.255.255.255/32"}},
		{"non-canonical-bl-no-overlap", []string{"10.0.0.5/24"}, []string{"99.0.0.0/8"}},
		{"non-canonical-bl-overlap", []string{"10.0.0.5/24"}, []string{"10.0.0.128/25"}},
		{"non-canonical-bl-covered", []string{"10.0.0.5/24"}, []string{"10.0.0.0/16"}},
		{"union-covers-not-single", []string{"10.0.0.0/24"}, []string{"10.0.0.0/25", "10.0.0.128/25"}},
		{"union-covers-three", []string{"10.0.0.0/24"}, []string{"10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/25"}},
		{"adjacent-union-covers", []string{"10.0.0.0/23"}, []string{"10.0.0.0/24", "10.0.1.0/24"}},
		{"wl-bigger-equal", []string{"10.0.0.0/24"}, []string{"10.0.0.0/24"}},
		{"multi-bl", []string{"10.0.0.0/24", "11.0.0.0/24", "12.0.0.0/8"}, []string{"10.0.0.128/25", "12.255.0.0/16"}},
		{"invalid-bl", []string{"not-a-cidr", "10.0.0.0/24"}, []string{"10.0.0.0/25"}},
		{"invalid-wl-only", []string{"10.0.0.0/24"}, []string{"garbage", "also-bad"}},
		{"dup-wl", []string{"10.0.0.0/16"}, []string{"10.0.1.0/24", "10.0.1.0/24", "10.0.2.0/24"}},
		{"wl-outside-right", []string{"10.0.0.0/24"}, []string{"10.0.1.0/24"}},
		{"interior-hole", []string{"10.0.0.0/24"}, []string{"10.0.0.64/26"}},
		{"two-interior", []string{"10.0.0.0/24"}, []string{"10.0.0.32/27", "10.0.0.128/26"}},
		{"wl-overlap-left-and-interior", []string{"10.0.16.0/20"}, []string{"10.0.0.0/20", "10.0.20.0/24", "10.0.31.128/25"}},
	}
	for _, c := range cases {
		old := oldRemoveWhitelisted(c.blacklist, c.whitelist)
		nw := RemoveWhitelisted(c.blacklist, c.whitelist)
		if !eq(old, nw) {
			t.Errorf("MISMATCH %s\n bl=%v\n wl=%v\n old=%v\n new=%v", c.name, c.blacklist, c.whitelist, old, nw)
		}
	}
}

func randCidrV4(r *rand.Rand) string {
	prefix := r.Intn(33) // 0..32
	ip := r.Uint32()
	return fmt.Sprintf("%d.%d.%d.%d/%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), prefix)
}

// Randomized fuzz with small address windows to force lots of overlaps,
// plus full-range entries.
func TestDiff_RandomFuzz(t *testing.T) {
	r := rand.New(rand.NewSource(12345))
	iters := 200000
	if testing.Short() {
		iters = 2000
	}
	for iter := 0; iter < iters; iter++ {
		nb := r.Intn(4) + 1
		nw := r.Intn(5)
		var bl, wl []string
		for i := 0; i < nb; i++ {
			bl = append(bl, randCidrV4(r))
		}
		for i := 0; i < nw; i++ {
			wl = append(wl, randCidrV4(r))
		}
		old := oldRemoveWhitelisted(bl, wl)
		new := RemoveWhitelisted(bl, wl)
		if !eq(old, new) {
			t.Fatalf("MISMATCH iter=%d\n bl=%v\n wl=%v\n old=%v\n new=%v", iter, bl, wl, old, new)
		}
	}
}

// Constrained fuzz: keep everything inside a tight /16 so overlap probability is high,
// many /24..../32 whitelist holes against /16../20 blacklist windows.
func TestDiff_TightFuzz(t *testing.T) {
	r := rand.New(rand.NewSource(99))
	iters := 200000
	if testing.Short() {
		iters = 2000
	}
	base := uint32(10) << 24
	mk := func(low uint32, prefix int) string {
		ip := base | (low & 0x00FFFFFF)
		return fmt.Sprintf("%d.%d.%d.%d/%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), prefix)
	}
	for iter := 0; iter < iters; iter++ {
		nb := r.Intn(3) + 1
		nw := r.Intn(6)
		var bl, wl []string
		for i := 0; i < nb; i++ {
			bl = append(bl, mk(r.Uint32(), 12+r.Intn(13))) // /12../24
		}
		for i := 0; i < nw; i++ {
			wl = append(wl, mk(r.Uint32(), 12+r.Intn(21))) // /12../32
		}
		old := oldRemoveWhitelisted(bl, wl)
		new := RemoveWhitelisted(bl, wl)
		if !eq(old, new) {
			t.Fatalf("MISMATCH iter=%d\n bl=%v\n wl=%v\n old=%v\n new=%v", iter, bl, wl, old, new)
		}
	}
}
