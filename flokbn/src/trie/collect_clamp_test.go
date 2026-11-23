package trie

import (
	"math"
	"math/rand"
	"reflect"
	"testing"
)

func ipv4u(a, b, c, d uint32) uint32 { return a<<24 | b<<16 | c<<8 | d }

// TestCollectCIDRsMinClusterSizeZero: minClusterSize 0 must behave exactly
// like 1. Every node below the Root has Count >= 1, so the two only differ at
// the Root, whose Count is never incremented (always 0): with a minimum of 0
// the Root passed the size gate and 0.0.0.0/0 - the whole address space - was
// emitted whenever the two halves of the space carried equal counts (or
// unconditionally with maxDepth 0).
func TestCollectCIDRsMinClusterSizeZero(t *testing.T) {
	t.Run("balanced halves do not emit the default route", func(t *testing.T) {
		tr := NewTrieSeq()
		tr.InsertUint32(ipv4u(0, 0, 0, 1))
		tr.InsertUint32(ipv4u(128, 0, 0, 1))

		got := tr.CollectCIDRs(0, 0, 32, 0.1)
		for _, c := range got {
			if c == "0.0.0.0/0" {
				t.Fatalf("minClusterSize 0 emitted 0.0.0.0/0: %v", got)
			}
		}
		if want := tr.CollectCIDRs(1, 0, 32, 0.1); !reflect.DeepEqual(got, want) {
			t.Errorf("minClusterSize 0 = %v, want the minClusterSize 1 result %v", got, want)
		}
	})

	t.Run("maxDepth 0 does not emit the default route", func(t *testing.T) {
		tr := NewTrieSeq()
		tr.InsertUint32(ipv4u(10, 0, 0, 1))
		if got := tr.CollectCIDRs(0, 0, 0, 0.1); len(got) != 0 {
			t.Errorf("CollectCIDRs(0,0,0) = %v, want none (same as minClusterSize 1)", got)
		}
	})

	t.Run("identical to minClusterSize 1 on random tries", func(t *testing.T) {
		rng := rand.New(rand.NewSource(7))
		for iter := 0; iter < 200; iter++ {
			tr := NewTrieSeq()
			n := 1 + rng.Intn(300)
			for i := 0; i < n; i++ {
				// Small window so shared prefixes and balanced nodes are common;
				// occasionally spread across both halves of the space.
				ip := ipv4u(10, 0, uint32(rng.Intn(4)), uint32(rng.Intn(256)))
				if rng.Intn(8) == 0 {
					ip |= 0x80000000
				}
				tr.InsertUint32(ip)
			}
			minDepth := uint32(rng.Intn(33))
			maxDepth := minDepth + uint32(rng.Intn(int(33-minDepth)))
			msd := float64(rng.Intn(2001)) / 1000
			got := tr.CollectCIDRs(0, minDepth, maxDepth, msd)
			want := tr.CollectCIDRs(1, minDepth, maxDepth, msd)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("iter %d (depth %d..%d, msd %v): minClusterSize 0 = %v, minClusterSize 1 = %v",
					iter, minDepth, maxDepth, msd, got, want)
			}
		}
	})
}

// TestCollectCIDRsThresholdConversion pins the meanSubnetDifference ->
// integer threshold conversion. A node with child counts a and b clusters iff
// 2*|a-b|/(a+b) < meanSubnetDifference (strict).
func TestCollectCIDRsThresholdConversion(t *testing.T) {
	// pair builds a trie holding 192.168.1.0 (a requests) and 192.168.1.1
	// (b requests) and reports whether their /31 parent is emitted.
	clusters := func(a, b uint32, msd float64) bool {
		tr := NewTrieSeq()
		tr.insertUint32WithCount(ipv4u(192, 168, 1, 0), a)
		tr.insertUint32WithCount(ipv4u(192, 168, 1, 1), b)
		for _, c := range tr.CollectCIDRs(a+b, 24, 32, msd) {
			if c == "192.168.1.0/31" {
				return true
			}
		}
		return false
	}

	tests := []struct {
		name string
		a, b uint32
		msd  float64
		want bool
	}{
		// 1.001*1000 is 1000.9999999999999 in float64: truncating it to 1000
		// lost the last digit, so an imbalance of exactly 1.0 did not cluster
		// under a threshold of 1.001.
		{"1.001 is not truncated to 1.000", 1500, 500, 1.001, true},
		{"1.000 still excludes the exact boundary", 1500, 500, 1.0, false},
		// Digits beyond the third decimal used to be dropped (0.0015 -> 0.001).
		// Imbalance here is 2*6/10000 = 0.0012.
		{"0.0015 is honoured below 0.001 resolution", 5003, 4997, 0.0015, true},
		{"0.0011 is not rounded up past the imbalance", 5003, 4997, 0.0011, false},
		{"0.0012 excludes the exact boundary", 5003, 4997, 0.0012, false},
		// Out-of-range inputs: float -> uint32 conversion is implementation
		// defined for NaN, Inf, negative and too-large values (it differs
		// between amd64 and arm64), so they are clamped first.
		{"NaN behaves like 0", 3, 2, math.NaN(), false},
		{"negative behaves like 0", 3, 2, -5, false},
		{"zero never clusters unequal counts", 3, 2, 0, false},
		{"+Inf clusters any imbalance", 1000000, 1, math.Inf(1), true},
		{"1e30 clusters any imbalance", 1000000, 1, 1e30, true},
		{"5e6 (past uint32 after scaling) clusters any imbalance", 1000000, 1, 5e6, true},
		{"2.0 clusters any imbalance", 1000000, 1, 2.0, true},
		{"equal counts cluster at any threshold", 7, 7, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clusters(tt.a, tt.b, tt.msd); got != tt.want {
				t.Errorf("counts %d/%d, meanSubnetDifference %v: clustered = %v, want %v", tt.a, tt.b, tt.msd, got, tt.want)
			}
		})
	}
}

// TestCollectCIDRsThresholdUnchangedForMilliValues: for every threshold that
// is a multiple of 0.001 the finer-grained integer threshold must decide
// exactly as the documented formula 2000*diff < k*count does (so results for
// ordinary configs such as 0.1 / 0.15 / 0.2 are unchanged).
func TestCollectCIDRsThresholdUnchangedForMilliValues(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	for iter := 0; iter < 20000; iter++ {
		k := uint64(rng.Intn(2001))
		a := uint32(1 + rng.Intn(5000))
		b := uint32(1 + rng.Intn(5000))
		if a == b {
			continue // equal counts take the fast path
		}
		diff := uint64(a) - uint64(b)
		if b > a {
			diff = uint64(b) - uint64(a)
		}
		want := 2000*diff < k*(uint64(a)+uint64(b))

		tr := NewTrieSeq()
		tr.insertUint32WithCount(ipv4u(192, 168, 1, 0), a)
		tr.insertUint32WithCount(ipv4u(192, 168, 1, 1), b)
		got := false
		for _, c := range tr.CollectCIDRs(a+b, 24, 32, float64(k)/1000) {
			if c == "192.168.1.0/31" {
				got = true
			}
		}
		if got != want {
			t.Fatalf("counts %d/%d, threshold %d/1000: clustered = %v, want %v", a, b, k, got, want)
		}
	}
}
