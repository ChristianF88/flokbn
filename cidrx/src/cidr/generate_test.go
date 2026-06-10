package cidr

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestLargestCIDRSize(t *testing.T) {
	tests := []struct {
		name     string
		start    uint32
		maxSize  uint32
		expected uint8
	}{
		{name: "zero maxSize at zero", start: 0, maxSize: 0, expected: 0},
		{name: "zero maxSize nonzero start", start: 5, maxSize: 0, expected: 0},
		{name: "single IP at zero", start: 0, maxSize: 1, expected: 0},
		{name: "single IP at 0x80000000", start: 0x80000000, maxSize: 1, expected: 0},
		{name: "full space minus one at zero", start: 0, maxSize: 0xFFFFFFFF, expected: 31},
		{name: "two IPs at zero", start: 0, maxSize: 2, expected: 1},
		{name: "256 IPs at zero", start: 0, maxSize: 256, expected: 8},
		{name: "257 IPs at zero", start: 0, maxSize: 257, expected: 8},
		{name: "odd start large maxSize", start: 1, maxSize: 0xFFFFFFFF, expected: 0},
		{name: "alignment limits size", start: 2, maxSize: 8, expected: 1},
		{name: "192.168.1.0 with 256", start: 0xC0A80100, maxSize: 256, expected: 8},
		{name: "192.168.1.128 with 256", start: 0xC0A80180, maxSize: 256, expected: 7},
		{name: "0x80000000 full maxSize", start: 0x80000000, maxSize: 0xFFFFFFFF, expected: 31},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LargestCIDRSize(tt.start, tt.maxSize)
			if got != tt.expected {
				t.Errorf("LargestCIDRSize(%#x, %d) = %d, want %d", tt.start, tt.maxSize, got, tt.expected)
			}
		})
	}
}

// expectedDescendingTiling builds the hand-derived expected tiling for
// [0, 0xFFFFFFFE]: 32 blocks of strictly descending size. Entry for prefix
// p (p = 1..31) starts where all larger blocks before it ended, which is
// IP = ^uint32(0) << (33 - p) for p >= 2 and IP = 0 for p = 1. The final
// entry is the single leftover IP {0xFFFFFFFE, 32}.
func expectedDescendingTiling() []NumericCIDR {
	want := make([]NumericCIDR, 0, 32)
	want = append(want, NumericCIDR{IP: 0, PrefixLen: 1})
	for p := uint8(2); p <= 31; p++ {
		want = append(want, NumericCIDR{IP: ^uint32(0) << (33 - p), PrefixLen: p})
	}
	want = append(want, NumericCIDR{IP: 0xFFFFFFFE, PrefixLen: 32})
	return want
}

// expectedAscendingTiling builds the hand-derived expected tiling for
// [1, 0xFFFFFFFF]: 32 blocks of strictly ascending size,
// {1,32},{2,31},{4,30},...,{0x80000000,1}. Entry k (k = 0..31) is
// IP = 1<<k with prefix 32-k.
func expectedAscendingTiling() []NumericCIDR {
	want := make([]NumericCIDR, 0, 32)
	for k := 0; k <= 31; k++ {
		want = append(want, NumericCIDR{IP: uint32(1) << k, PrefixLen: uint8(32 - k)})
	}
	return want
}

func TestGenerateOptimalNumeric(t *testing.T) {
	tests := []struct {
		name     string
		start    uint32
		end      uint32
		expected []NumericCIDR
	}{
		{
			name:     "inverted range",
			start:    5,
			end:      4,
			expected: nil,
		},
		{
			name:     "inverted range extremes",
			start:    0xFFFFFFFF,
			end:      0,
			expected: nil,
		},
		{
			name:     "single IP zero",
			start:    0,
			end:      0,
			expected: []NumericCIDR{{IP: 0, PrefixLen: 32}},
		},
		{
			name:     "single IP max",
			start:    0xFFFFFFFF,
			end:      0xFFFFFFFF,
			expected: []NumericCIDR{{IP: 0xFFFFFFFF, PrefixLen: 32}},
		},
		{
			name:     "full address space yields /0",
			start:    0,
			end:      0xFFFFFFFF,
			expected: []NumericCIDR{{IP: 0, PrefixLen: 0}},
		},
		{
			name:     "full space minus top IP descending tiling",
			start:    0,
			end:      0xFFFFFFFE,
			expected: expectedDescendingTiling(),
		},
		{
			name:     "full space minus bottom IP ascending tiling",
			start:    1,
			end:      0xFFFFFFFF,
			expected: expectedAscendingTiling(),
		},
		{
			name:  "unaligned mid range 192.168.1.1 - 192.168.2.6",
			start: 0xC0A80101,
			end:   0xC0A80206,
			expected: []NumericCIDR{
				{IP: 0xC0A80101, PrefixLen: 32},
				{IP: 0xC0A80102, PrefixLen: 31},
				{IP: 0xC0A80104, PrefixLen: 30},
				{IP: 0xC0A80108, PrefixLen: 29},
				{IP: 0xC0A80110, PrefixLen: 28},
				{IP: 0xC0A80120, PrefixLen: 27},
				{IP: 0xC0A80140, PrefixLen: 26},
				{IP: 0xC0A80180, PrefixLen: 25},
				{IP: 0xC0A80200, PrefixLen: 30},
				{IP: 0xC0A80204, PrefixLen: 31},
				{IP: 0xC0A80206, PrefixLen: 32},
			},
		},
		{
			name:     "aligned /8",
			start:    0x0A000000,
			end:      0x0AFFFFFF,
			expected: []NumericCIDR{{IP: 0x0A000000, PrefixLen: 8}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateOptimalNumeric(tt.start, tt.end)
			if len(got) != len(tt.expected) {
				t.Fatalf("GenerateOptimalNumeric(%#x, %#x) returned %d CIDRs, want %d: got %v",
					tt.start, tt.end, len(got), len(tt.expected), got)
			}
			for i := range tt.expected {
				if got[i] != tt.expected[i] {
					t.Errorf("GenerateOptimalNumeric(%#x, %#x)[%d] = {%#x, %d}, want {%#x, %d}",
						tt.start, tt.end, i,
						got[i].IP, got[i].PrefixLen,
						tt.expected[i].IP, tt.expected[i].PrefixLen)
				}
			}
		})
	}
}

func TestGenerateOptimal(t *testing.T) {
	tests := []struct {
		name     string
		start    uint32
		end      uint32
		expected []string
	}{
		{
			name:     "full address space",
			start:    0,
			end:      0xFFFFFFFF,
			expected: []string{"0.0.0.0/0"},
		},
		{
			name:     "aligned /8",
			start:    0x0A000000,
			end:      0x0AFFFFFF,
			expected: []string{"10.0.0.0/8"},
		},
		{
			name:     "single IP zero",
			start:    0,
			end:      0,
			expected: []string{"0.0.0.0/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateOptimal(tt.start, tt.end)
			if len(got) != len(tt.expected) {
				t.Fatalf("GenerateOptimal(%#x, %#x) = %v, want %v", tt.start, tt.end, got, tt.expected)
			}
			for i := range tt.expected {
				if got[i] != tt.expected[i] {
					t.Errorf("GenerateOptimal(%#x, %#x)[%d] = %q, want %q",
						tt.start, tt.end, i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestSubtractMultiple(t *testing.T) {
	tests := []struct {
		name      string
		blacklist string
		whitelist []string
		expected  []string
	}{
		{
			name:      "invalid whitelist entries silently skipped",
			blacklist: "10.0.0.0/8",
			whitelist: []string{"not-a-cidr", "999.1.2.3/8"},
			expected:  []string{"10.0.0.0/8"},
		},
		{
			name:      "invalid blacklist passthrough",
			blacklist: "garbage",
			whitelist: []string{"10.0.0.0/8"},
			expected:  []string{"garbage"},
		},
		{
			name:      "whitelist fully covers blacklist",
			blacklist: "10.1.0.0/16",
			whitelist: []string{"10.0.0.0/8"},
			expected:  []string{},
		},
		{
			name:      "no intersection",
			blacklist: "10.0.1.0/24",
			whitelist: []string{"10.0.0.0/25"},
			expected:  []string{"10.0.1.0/24"},
		},
		{
			name:      "hole in the middle",
			blacklist: "10.0.1.0/24",
			whitelist: []string{"10.0.1.64/26"},
			expected:  []string{"10.0.1.0/26", "10.0.1.128/25"},
		},
		{
			name:      "adjacent whitelists merge",
			blacklist: "10.0.0.0/24",
			whitelist: []string{"10.0.0.64/26", "10.0.0.128/26"},
			expected:  []string{"10.0.0.0/26", "10.0.0.192/26"},
		},
		{
			name:      "exclusion ends at top of address space",
			blacklist: "255.255.255.0/24",
			whitelist: []string{"255.255.255.128/25"},
			expected:  []string{"255.255.255.0/25"},
		},
		{
			name:      "full space minus full space",
			blacklist: "0.0.0.0/0",
			whitelist: []string{"0.0.0.0/0"},
			expected:  []string{},
		},
		{
			name:      "full space minus upper half",
			blacklist: "0.0.0.0/0",
			whitelist: []string{"128.0.0.0/1"},
			expected:  []string{"0.0.0.0/1"},
		},
		{
			name:      "top /30 minus top /31",
			blacklist: "255.255.255.252/30",
			whitelist: []string{"255.255.255.254/31"},
			expected:  []string{"255.255.255.252/31"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SubtractMultiple(tt.blacklist, tt.whitelist)
			if err != nil {
				t.Fatalf("SubtractMultiple(%q, %v) returned error: %v", tt.blacklist, tt.whitelist, err)
			}
			if len(got) != len(tt.expected) {
				t.Fatalf("SubtractMultiple(%q, %v) = %v, want %v", tt.blacklist, tt.whitelist, got, tt.expected)
			}
			for i := range tt.expected {
				if got[i] != tt.expected[i] {
					t.Errorf("SubtractMultiple(%q, %v)[%d] = %q, want %q",
						tt.blacklist, tt.whitelist, i, got[i], tt.expected[i])
				}
			}
		})
	}
}

// assertExactTiling verifies (with uint64 arithmetic, immune to uint32 wrap)
// that cidrs tiles exactly the inclusive range [start, end]: ascending order,
// power-of-two sizes, size-aligned IPs, no gaps, no overlaps.
func assertExactTiling(t *testing.T, start, end uint32, cidrs []NumericCIDR) {
	t.Helper()

	if len(cidrs) == 0 {
		t.Fatalf("range [%#x, %#x]: empty result", start, end)
	}

	expectedNext := uint64(start)
	for i, c := range cidrs {
		if c.PrefixLen > 32 {
			t.Fatalf("range [%#x, %#x]: block %d has invalid prefix %d", start, end, i, c.PrefixLen)
		}
		size := uint64(1) << (32 - c.PrefixLen)
		ip := uint64(c.IP)

		if ip != expectedNext {
			t.Fatalf("range [%#x, %#x]: block %d starts at %#x, want %#x (gap or overlap)",
				start, end, i, ip, expectedNext)
		}
		if ip%size != 0 {
			t.Fatalf("range [%#x, %#x]: block %d IP %#x not aligned to size %d",
				start, end, i, ip, size)
		}
		expectedNext = ip + size
	}

	if expectedNext-1 != uint64(end) {
		t.Fatalf("range [%#x, %#x]: tiling ends at %#x, want %#x",
			start, end, expectedNext-1, uint64(end))
	}
}

func TestGenerateOptimalNumericProperties(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	type pair struct{ start, end uint32 }
	pairs := make([]pair, 0, 2100)

	// Always include the full address space explicitly.
	pairs = append(pairs, pair{0, 0xFFFFFFFF})

	// Uniform random pairs.
	for i := 0; i < 800; i++ {
		a, b := rng.Uint32(), rng.Uint32()
		if a > b {
			a, b = b, a
		}
		pairs = append(pairs, pair{a, b})
	}
	// Small ranges.
	for i := 0; i < 600; i++ {
		a := rng.Uint32()
		span := uint32(rng.Intn(1000))
		b := a + span
		if b < a { // wrapped; clamp to top
			b = 0xFFFFFFFF
		}
		pairs = append(pairs, pair{a, b})
	}
	// Ranges hugging 0.
	for i := 0; i < 300; i++ {
		a := uint32(rng.Intn(65))
		b := rng.Uint32()
		if b < a {
			b = a
		}
		pairs = append(pairs, pair{a, b})
	}
	// Ranges hugging 0xFFFFFFFF.
	for i := 0; i < 300; i++ {
		b := uint32(0xFFFFFFC0) + uint32(rng.Intn(64))
		a := rng.Uint32()
		if a > b {
			a = b
		}
		pairs = append(pairs, pair{a, b})
	}

	for _, p := range pairs {
		result := GenerateOptimalNumeric(p.start, p.end)
		assertExactTiling(t, p.start, p.end, result)
		if len(result) > 62 {
			t.Fatalf("range [%#x, %#x]: %d blocks exceeds bound of 62", p.start, p.end, len(result))
		}
	}

	// Minimality spot rows: [0, 2^k - 1] must always be a single block.
	for k := 0; k <= 32; k++ {
		end := uint32(uint64(1)<<k - 1)
		result := GenerateOptimalNumeric(0, end)
		if len(result) != 1 {
			t.Fatalf("range [0, 2^%d-1]: got %d blocks, want 1: %v", k, len(result), result)
		}
		want := NumericCIDR{IP: 0, PrefixLen: uint8(32 - k)}
		if result[0] != want {
			t.Fatalf("range [0, 2^%d-1]: got {%#x, %d}, want {%#x, %d}",
				k, result[0].IP, result[0].PrefixLen, want.IP, want.PrefixLen)
		}
	}
}

var (
	benchSinkStrings []string
	benchSinkNumeric []NumericCIDR
)

func BenchmarkSubtractMultiple(b *testing.B) {
	b.Run("no_intersection", func(b *testing.B) {
		whitelist := make([]string, 0, 8)
		for i := 0; i < 8; i++ {
			whitelist = append(whitelist, fmt.Sprintf("192.168.%d.0/24", i*10))
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchSinkStrings, _ = SubtractMultiple("10.5.0.0/16", whitelist)
		}
	})

	b.Run("24black_8white", func(b *testing.B) {
		whitelist := []string{
			"10.5.1.0/24",
			"10.5.20.0/24",
			"10.5.40.17/32",
			"10.5.80.0/24",
			"10.5.130.5/32",
			"10.5.131.0/24",
			"10.5.200.0/24",
			"10.5.250.99/32",
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchSinkStrings, _ = SubtractMultiple("10.5.0.0/16", whitelist)
		}
	})

	b.Run("50whitelist", func(b *testing.B) {
		whitelist := make([]string, 0, 50)
		for i := 0; i < 50; i++ {
			// Pairs of adjacent /24s (x.0.0/24 and x.1.0/24) to exercise merging,
			// scattered across distinct second octets.
			whitelist = append(whitelist, fmt.Sprintf("10.%d.%d.0/24", (i/2)*5+1, i%2))
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchSinkStrings, _ = SubtractMultiple("10.0.0.0/8", whitelist)
		}
	})
}

func BenchmarkGenerateOptimalNumeric(b *testing.B) {
	cases := []struct {
		name  string
		start uint32
		end   uint32
	}{
		{name: "single_ip", start: 5, end: 5},
		{name: "aligned_16", start: 0x0A050000, end: 0x0A05FFFF},
		{name: "worst_case_unaligned", start: 1, end: 0xFFFFFFFE},
		{name: "full_space", start: 0, end: 0xFFFFFFFF},
	}

	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchSinkNumeric = GenerateOptimalNumeric(c.start, c.end)
			}
		})
	}
}
