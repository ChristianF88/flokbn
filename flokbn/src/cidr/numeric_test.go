package cidr

import (
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"testing"

	"github.com/ChristianF88/flokbn/iputils"
)

// refParse is the definition Parse is held to: net.ParseCIDR plus the IPv4-only
// gate on the mask length that the cidr package applied at every call site
// before Parse existed.
func refParse(s string) (NumericCIDR, bool) {
	_, n, err := net.ParseCIDR(s)
	if err != nil || len(n.Mask) != 4 {
		return NumericCIDR{}, false
	}
	ones, _ := n.Mask.Size()
	return NumericCIDR{IP: iputils.IPToUint32(n.IP), PrefixLen: uint8(ones)}, true
}

// parseCorpus holds spellings around every decision of parseCanonical: octet
// width and range, leading zeros, separators, prefix width and range, host
// bits, and the non-IPv4 forms net.ParseCIDR accepts.
var parseCorpus = []string{
	"10.0.0.0/8", "10.0.0.77/24", "0.0.0.0/0", "255.255.255.255/32", "1.2.3.4/31",
	"192.168.1.1/0", "128.0.0.0/1", "255.255.255.255/0", "9.9.9.9/9", "100.64.0.0/10",
	// zero-padded prefix lengths: valid for net.ParseCIDR, slow path
	"10.0.0.0/08", "10.0.0.0/008", "10.0.0.0/00", "10.0.0.0/032", "10.0.0.0/0000000024",
	// out of range
	"10.0.0.0/33", "10.0.0.0/99", "10.0.0.0/100", "256.0.0.0/8", "10.0.0.256/8", "999.1.1.1/8",
	"1000.1.1.1/8",
	// leading zeros in octets (rejected since Go 1.17)
	"010.0.0.0/8", "10.00.0.0/8", "10.0.0.01/8", "00.0.0.0/8",
	// malformed
	"", "/", "/8", "10.0.0.0", "10.0.0.0/", "10.0.0/8", "10.0.0.0.0/8", "10..0.0/8", ".10.0.0.0/8",
	"10.0.0.0//8", "10.0.0.0/8/", "10.0.0.0/+8", "10.0.0.0/-1", "10.0.0.0/ 8", " 10.0.0.0/8",
	"10.0.0.0/8 ", "10.0.0.0/8\n", "10.0.0.0/a", "a.b.c.d/8", "10.0.0.0\\8", "10,0,0,0/8",
	"１０.0.0.0/8", "10.0.0.0/８", "not-a-cidr", "10.0.0.x/8", "1.2.3.4/3x", "1.2.3.4/x3",
	// IPv6 and IPv4-mapped IPv6: parse, but are not IPv4
	"::/0", "::1/128", "2001:db8::/32", "::ffff:10.0.0.0/120", "::ffff:10.0.0.0/104", "fe80::1%eth0/64",
}

func TestParse_MatchesNetParseCIDR(t *testing.T) {
	check := func(s string) {
		t.Helper()
		got, gotOK := Parse(s)
		want, wantOK := refParse(s)
		if got != want || gotOK != wantOK {
			t.Fatalf("Parse(%q) = %+v, %v; net.ParseCIDR gives %+v, %v", s, got, gotOK, want, wantOK)
		}
	}
	for _, s := range parseCorpus {
		check(s)
	}

	// Every address/prefix combination of a few addresses, canonical spelling.
	for _, ip := range []uint32{0, 1, 0x0A00004D, 0x7FFFFFFF, 0x80000000, 0xC0A80101, 0xFFFFFFFE, 0xFFFFFFFF} {
		for prefix := 0; prefix <= 40; prefix++ {
			check(fmt.Sprintf("%d.%d.%d.%d/%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), prefix))
		}
	}

	// Random valid CIDRs, and the same strings with one byte changed, dropped
	// or doubled.
	rng := rand.New(rand.NewSource(7))
	const alphabet = "0123456789./: x"
	for i := 0; i < 200000; i++ {
		s := randCidrV4(rng)
		check(s)
		b := []byte(s)
		pos := rng.Intn(len(b))
		switch rng.Intn(3) {
		case 0:
			b[pos] = alphabet[rng.Intn(len(alphabet))]
		case 1:
			b = append(b[:pos], b[pos+1:]...)
		default:
			b = append(b[:pos+1], b[pos:]...)
		}
		check(string(b))
	}
}

// FuzzParse holds Parse to net.ParseCIDR plus the 4-byte-mask gate for
// arbitrary input.
func FuzzParse(f *testing.F) {
	for _, s := range parseCorpus {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, gotOK := Parse(s)
		want, wantOK := refParse(s)
		if got != want || gotOK != wantOK {
			t.Fatalf("Parse(%q) = %+v, %v; net.ParseCIDR gives %+v, %v", s, got, gotOK, want, wantOK)
		}
	})
}

func TestParse_CanonicalSpellingDoesNotAllocate(t *testing.T) {
	for _, s := range []string{"10.0.0.0/8", "255.255.255.255/32", "0.0.0.0/0", "192.168.17.5/24"} {
		if allocs := testing.AllocsPerRun(100, func() { Parse(s) }); allocs != 0 {
			t.Errorf("Parse(%q) allocates %v times, want 0", s, allocs)
		}
	}
}

func TestNumericCIDR_Interval(t *testing.T) {
	tests := []struct {
		in   NumericCIDR
		want Interval
	}{
		{NumericCIDR{IP: 0x0A000000, PrefixLen: 8}, Interval{0x0A000000, 0x0AFFFFFF}},
		{NumericCIDR{IP: 0x0A000000, PrefixLen: 24}, Interval{0x0A000000, 0x0A0000FF}},
		{NumericCIDR{IP: 0x0A00004D, PrefixLen: 24}, Interval{0x0A000000, 0x0A0000FF}}, // host bits ignored
		{NumericCIDR{IP: 0x0A00004D, PrefixLen: 32}, Interval{0x0A00004D, 0x0A00004D}},
		{NumericCIDR{IP: 0, PrefixLen: 0}, Interval{0, 0xFFFFFFFF}},
		{NumericCIDR{IP: 0x80000000, PrefixLen: 1}, Interval{0x80000000, 0xFFFFFFFF}},
		{NumericCIDR{IP: 0xFFFFFFFE, PrefixLen: 31}, Interval{0xFFFFFFFE, 0xFFFFFFFF}},
		{NumericCIDR{IP: 0xFFFFFFFF, PrefixLen: 32}, Interval{0xFFFFFFFF, 0xFFFFFFFF}},
	}
	for _, tt := range tests {
		if got := tt.in.Interval(); got != tt.want {
			t.Errorf("%s.Interval() = %#x..%#x, want %#x..%#x", tt.in, got.Start, got.End, tt.want.Start, tt.want.End)
		}
	}
}

// TestParseIntervalSet checks the built sets against hand-computed intervals,
// including adjacency and overlap coalescing, the address-space boundaries, a
// /0, and skipped entries (malformed and IPv6), and probes Contains at and
// around every edge.
func TestParseIntervalSet(t *testing.T) {
	cases := []struct {
		name      string
		cidrs     []string
		want      IntervalSet
		inside    []uint32
		outsideIP []uint32
	}{
		{
			name:      "empty",
			cidrs:     nil,
			want:      nil,
			outsideIP: []uint32{0, 0x0A000000, 0xFFFFFFFF},
		},
		{
			name:      "single /24",
			cidrs:     []string{"10.0.0.0/24"},
			want:      IntervalSet{{0x0A000000, 0x0A0000FF}},
			inside:    []uint32{0x0A000000, 0x0A000080, 0x0A0000FF},
			outsideIP: []uint32{0x09FFFFFF, 0x0A000100, 0, 0xFFFFFFFF},
		},
		{
			name:      "host bits are masked",
			cidrs:     []string{"10.0.0.77/24"},
			want:      IntervalSet{{0x0A000000, 0x0A0000FF}},
			inside:    []uint32{0x0A000000, 0x0A00004D, 0x0A0000FF},
			outsideIP: []uint32{0x09FFFFFF, 0x0A000100},
		},
		{
			name:      "adjacent halves coalesce",
			cidrs:     []string{"10.0.0.128/25", "10.0.0.0/25"},
			want:      IntervalSet{{0x0A000000, 0x0A0000FF}},
			inside:    []uint32{0x0A000000, 0x0A00007F, 0x0A000080, 0x0A0000FF},
			outsideIP: []uint32{0x09FFFFFF, 0x0A000100},
		},
		{
			name:      "adjacent ranges of unequal size coalesce",
			cidrs:     []string{"10.0.0.0/7", "12.0.0.0/10"},
			want:      IntervalSet{{0x0A000000, 0x0C3FFFFF}},
			inside:    []uint32{0x0A000000, 0x0BFFFFFF, 0x0C000000, 0x0C3FFFFF},
			outsideIP: []uint32{0x09FFFFFF, 0x0C400000},
		},
		{
			name:      "nested range is absorbed",
			cidrs:     []string{"10.0.0.0/8", "10.20.0.0/16", "10.20.30.0/24"},
			want:      IntervalSet{{0x0A000000, 0x0AFFFFFF}},
			inside:    []uint32{0x0A000000, 0x0A141E00, 0x0AFFFFFF},
			outsideIP: []uint32{0x09FFFFFF, 0x0B000000},
		},
		{
			name:      "duplicate entries",
			cidrs:     []string{"192.168.1.0/24", "192.168.1.0/24"},
			want:      IntervalSet{{0xC0A80100, 0xC0A801FF}},
			inside:    []uint32{0xC0A80100, 0xC0A801FF},
			outsideIP: []uint32{0xC0A800FF, 0xC0A80200},
		},
		{
			name:      "gap between ranges stays a gap",
			cidrs:     []string{"10.0.1.0/24", "10.0.0.0/25"},
			want:      IntervalSet{{0x0A000000, 0x0A00007F}, {0x0A000100, 0x0A0001FF}},
			inside:    []uint32{0x0A000000, 0x0A00007F, 0x0A000100, 0x0A0001FF},
			outsideIP: []uint32{0x09FFFFFF, 0x0A000080, 0x0A0000FF, 0x0A000200},
		},
		{
			name:      "bottom of the address space",
			cidrs:     []string{"0.0.0.0/30"},
			want:      IntervalSet{{0x00000000, 0x00000003}},
			inside:    []uint32{0, 3},
			outsideIP: []uint32{4, 0xFFFFFFFF},
		},
		{
			name:      "top of the address space",
			cidrs:     []string{"255.255.255.252/30"},
			want:      IntervalSet{{0xFFFFFFFC, 0xFFFFFFFF}},
			inside:    []uint32{0xFFFFFFFC, 0xFFFFFFFF},
			outsideIP: []uint32{0xFFFFFFFB, 0},
		},
		{
			name:      "range reaching the top absorbs what follows",
			cidrs:     []string{"128.0.0.0/1", "255.255.255.255/32", "200.0.0.0/8"},
			want:      IntervalSet{{0x80000000, 0xFFFFFFFF}},
			inside:    []uint32{0x80000000, 0xC8000000, 0xFFFFFFFF},
			outsideIP: []uint32{0x7FFFFFFF, 0},
		},
		{
			name:   "/0 covers everything",
			cidrs:  []string{"10.0.0.0/8", "0.0.0.0/0"},
			want:   IntervalSet{{0x00000000, 0xFFFFFFFF}},
			inside: []uint32{0, 0x0A000000, 0x7FFFFFFF, 0xFFFFFFFF},
		},
		{
			name:      "malformed and IPv6 entries are skipped",
			cidrs:     []string{"not-a-cidr", "::/0", "::ffff:10.0.0.0/120", "2001:db8::/32", "10.0.0.0/24", ""},
			want:      IntervalSet{{0x0A000000, 0x0A0000FF}},
			inside:    []uint32{0x0A000000, 0x0A0000FF},
			outsideIP: []uint32{0, 0x09FFFFFF, 0x0A000100, 0xFFFFFFFF},
		},
		{
			name:      "only skipped entries",
			cidrs:     []string{"garbage", "::/0"},
			want:      nil,
			outsideIP: []uint32{0, 0x0A000000, 0xFFFFFFFF},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := ParseIntervalSet(tc.cidrs)
			if len(set) != len(tc.want) || (len(set) > 0 && !reflect.DeepEqual(set, tc.want)) {
				t.Fatalf("ParseIntervalSet(%v) = %v, want %v", tc.cidrs, set, tc.want)
			}
			for _, ip := range tc.inside {
				if !set.Contains(ip) {
					t.Errorf("Contains(%#x) = false, want true", ip)
				}
			}
			for _, ip := range tc.outsideIP {
				if set.Contains(ip) {
					t.Errorf("Contains(%#x) = true, want false", ip)
				}
			}
		})
	}
}

// TestIntervalSet_ZeroValue: the nil set is the empty set.
func TestIntervalSet_ZeroValue(t *testing.T) {
	var set IntervalSet
	for _, ip := range []uint32{0, 1, 0x0A000000, 0xFFFFFFFF} {
		if set.Contains(ip) {
			t.Errorf("empty set Contains(%#x) = true", ip)
		}
	}
	if set.covers(0, 0) || set.intersects(0, 0xFFFFFFFF) {
		t.Error("empty set covers or intersects a range")
	}
	if got := NewIntervalSet(nil); len(got) != 0 {
		t.Errorf("NewIntervalSet(nil) = %v, want empty", got)
	}
}

// TestIntervalSet_MatchesNetContains compares Contains with net.IPNet.Contains
// over random CIDR lists, probing every range edge and its neighbours plus
// random addresses.
func TestIntervalSet_MatchesNetContains(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for iter := 0; iter < 2000; iter++ {
		n := rng.Intn(12)
		cidrs := make([]string, 0, n)
		var nets []*net.IPNet
		var probes []uint32
		for i := 0; i < n; i++ {
			var s string
			if rng.Intn(2) == 0 {
				// A tight window, so ranges overlap and touch.
				prefix := 20 + rng.Intn(13)
				s = NumericCIDR{IP: 0x0A000000 + uint32(rng.Intn(1<<12)), PrefixLen: uint8(prefix)}.String()
			} else {
				s = randCidrV4(rng)
			}
			cidrs = append(cidrs, s)
			_, ipNet, err := net.ParseCIDR(s)
			if err != nil {
				t.Fatalf("ParseCIDR(%q): %v", s, err)
			}
			nets = append(nets, ipNet)
			nc, _ := Parse(s)
			iv := nc.Interval()
			probes = append(probes, iv.Start, iv.Start-1, iv.Start+1, iv.End, iv.End-1, iv.End+1)
		}
		for i := 0; i < 16; i++ {
			probes = append(probes, rng.Uint32(), 0x0A000000+uint32(rng.Intn(1<<12)))
		}
		probes = append(probes, 0, 0xFFFFFFFF)

		set := ParseIntervalSet(cidrs)
		for i := 1; i < len(set); i++ {
			if set[i-1].End == 0xFFFFFFFF || set[i].Start <= set[i-1].End+1 {
				t.Fatalf("set of %v is not sorted, disjoint and non-adjacent: %v", cidrs, set)
			}
		}
		for _, ip := range probes {
			want := false
			for _, ipNet := range nets {
				if ipNet.Contains(iputils.Uint32ToIP(ip)) {
					want = true
					break
				}
			}
			if got := set.Contains(ip); got != want {
				t.Fatalf("set of %v: Contains(%#x) = %v, want %v", cidrs, ip, got, want)
			}
		}
	}
}

// numericCIDRs parses CIDR strings into their numeric form.
func numericCIDRs(tb testing.TB, cidrs []string) []NumericCIDR {
	tb.Helper()
	out := make([]NumericCIDR, 0, len(cidrs))
	for _, c := range cidrs {
		nc, ok := Parse(c)
		if !ok {
			tb.Fatalf("invalid CIDR %s", c)
		}
		out = append(out, nc)
	}
	return out
}

// numericCIDRStrings stringifies numeric CIDRs. nil for none, like
// ipNetsToStrings.
func numericCIDRStrings(cidrs []NumericCIDR) []string {
	var out []string
	for _, nc := range cidrs {
		out = append(out, nc.String())
	}
	return out
}

// mergeCIDRStrings runs MergeCIDRs on CIDR strings and returns the result as
// strings.
func mergeCIDRStrings(tb testing.TB, cidrs []string) []string {
	tb.Helper()
	return numericCIDRStrings(MergeCIDRs(numericCIDRs(tb, cidrs)))
}

// randMergeInput draws a CIDR list for the merge tests. Three shapes: a tight
// window where containment, adjacency and sibling chains are dense (with an
// occasional top-of-space range), short prefixes that collapse towards /0, and
// uniformly random ranges. Some lists are sorted, so the already-clean fast
// path is hit as well.
func randMergeInput(rng *rand.Rand) []string {
	n := 1 + rng.Intn(24)
	shape := rng.Intn(4)
	in := make([]NumericCIDR, 0, n)
	for i := 0; i < n; i++ {
		var prefix int
		var base uint32
		switch shape {
		case 0, 1:
			prefix = 22 + rng.Intn(11) // /22../32
			base = uint32(0x0A000000) + uint32(rng.Intn(1<<11))
			if rng.Intn(16) == 0 {
				base = 0xFFFFF800 + uint32(rng.Intn(1<<11))
			}
		case 2:
			prefix = rng.Intn(5) // /0../4
			base = rng.Uint32()
		default:
			prefix = rng.Intn(33)
			base = rng.Uint32()
		}
		base &^= ^uint32(0) >> prefix // a shift by 32 yields 0: /32 keeps every bit
		in = append(in, NumericCIDR{IP: base, PrefixLen: uint8(prefix)})
		if rng.Intn(12) == 0 {
			in = append(in, in[rng.Intn(len(in))]) // duplicate
		}
	}
	if rng.Intn(3) == 0 {
		for i := 1; i < len(in); i++ {
			for j := i; j > 0 && in[j-1].IP > in[j].IP; j-- {
				in[j-1], in[j] = in[j], in[j-1]
			}
		}
	}
	return numericCIDRStrings(in)
}

// TestMergeCIDRs_MatchesMergeIPNets is the differential test for the numeric
// merge: same ranges, same order as the *net.IPNet implementation it replaced
// (the oracle in merge_ref_test.go), for curated and random inputs.
func TestMergeCIDRs_MatchesMergeIPNets(t *testing.T) {
	check := func(in []string) {
		t.Helper()
		mergeBoth(t, in)
	}

	for _, in := range [][]string{
		nil,
		{"10.0.0.0/24"},
		{"0.0.0.0/0"},
		{"0.0.0.0/0", "10.0.0.0/8"},
		{"10.0.0.0/8", "0.0.0.0/0"},
		{"0.0.0.0/0", "0.0.0.0/0"},
		{"0.0.0.0/1", "128.0.0.0/1"},
		{"128.0.0.0/1", "0.0.0.0/1"},
		{"0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3", "224.0.0.0/3"},
		{"255.255.255.0/24", "255.255.255.128/25"},
		{"255.255.255.254/31", "255.255.255.255/32"},
		{"255.255.255.254/32", "255.255.255.255/32"},
		{"255.255.255.255/32", "255.255.255.254/32"},
		{"128.0.0.0/1", "255.255.255.255/32"},
		{"192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"},
		{"10.0.0.0/16", "10.0.0.0/8", "192.168.1.0/25", "192.168.1.0/24"},
		{"10.0.0.0/24", "10.0.1.0/25", "10.0.1.128/26", "10.0.1.192/26"},
		{"10.0.1.192/26", "10.0.1.0/25", "10.0.0.0/24", "10.0.1.128/26"},
		{"255.255.254.0/24", "255.255.255.0/25", "255.255.255.128/26", "255.255.255.192/26"},
		// adjacent but not siblings: stay separate
		{"10.0.1.0/24", "10.0.2.0/24"},
		{"10.0.0.0/7", "12.0.0.0/10"},
		// ascending, disjoint, not touching: returned as is
		{"10.0.0.0/24", "10.0.2.0/24", "10.0.4.0/24"},
		// same, descending
		{"10.0.4.0/24", "10.0.2.0/24", "10.0.0.0/24"},
		// duplicates, same address with different prefixes
		{"10.0.0.0/24", "10.0.0.0/24"},
		{"10.0.0.0/24", "10.0.0.0/16", "10.0.0.0/32", "10.0.0.0/8"},
		{"1.1.1.1/32", "1.1.1.0/32", "1.1.1.2/32", "1.1.1.3/32"},
	} {
		check(in)
	}

	rng := rand.New(rand.NewSource(20261124))
	iters := 100000
	if testing.Short() {
		iters = 5000
	}
	for i := 0; i < iters; i++ {
		check(randMergeInput(rng))
	}
}

// TestMergeCIDRs_InPlace documents the aliasing contract: the input slice is
// reordered and the result shares its backing array.
func TestMergeCIDRs_InPlace(t *testing.T) {
	in := numericCIDRs(t, []string{"10.0.1.0/24", "192.168.0.0/16", "10.0.0.0/24"})
	out := MergeCIDRs(in)
	want := []string{"10.0.0.0/23", "192.168.0.0/16"}
	if got := numericCIDRStrings(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("MergeCIDRs = %v, want %v", got, want)
	}
	if &out[0] != &in[0] {
		t.Error("MergeCIDRs result does not alias its input")
	}
	if allocs := testing.AllocsPerRun(100, func() {
		in = append(in[:0], NumericCIDR{IP: 0x0A000100, PrefixLen: 24}, NumericCIDR{IP: 0xC0A80000, PrefixLen: 16}, NumericCIDR{IP: 0x0A000000, PrefixLen: 24})
		MergeCIDRs(in)
	}); allocs != 0 {
		t.Errorf("MergeCIDRs allocates %v times, want 0", allocs)
	}
}

// BenchmarkParse compares the numeric parser with net.ParseCIDR on the
// spelling flokbn writes itself.
func BenchmarkParse(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	inputs := make([]string, 1024)
	for i := range inputs {
		inputs[i] = randCidrV4(rng)
	}
	b.Run("Parse", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			Parse(inputs[i&1023])
		}
	})
	b.Run("net.ParseCIDR", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _, _ = net.ParseCIDR(inputs[i&1023])
		}
	})
}
