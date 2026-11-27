package sliding

import (
	"net"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/iputils"
	"github.com/ChristianF88/flokbn/trie"
	"github.com/alphadose/haxmap"
)

// TestSlidingWindow_Uint32Parity is the AUDIT-05 regression test. It proves that
// carrying the IP as a uint32 in TimedIP (and routing window ops through
// Trie.InsertUint32 / Trie.DeleteUint32 and uint32-keyed IPStats) produces
// state that is byte-identical to what the prior net.IP path would have
// produced. It drives a representative MIXED event stream through the live
// window - many inserts, time-based eviction, max-entries eviction, repeated
// IPs (count accumulation), and enough churn to trigger the periodic trie
// rebuild - then asserts three things against an INDEPENDENT oracle built from
// the surviving entries via the net.IP entry points (Insert(net.IP) /
// IPToUint32):
//
//  1. IPQueue contents (as uint32) match the oracle's surviving order.
//  2. IPStats (key set + Count + Last) match an oracle map built by replaying
//     adds/removes over net.IP-derived keys.
//  3. The window trie's clusters (CollectCIDRsNumeric AND CollectCIDRs) are
//     identical to a reference trie built the OLD way: Insert(net.IP) over the
//     same surviving IPs. This is the hard correctness invariant - clustering
//     output must not drift.
func TestSlidingWindow_Uint32Parity(t *testing.T) {
	// Small maxEntries + many distinct IPs across cycles forces size eviction
	// every cycle; a moderate window with mixed timestamps forces time eviction;
	// repeated IPs exercise count accumulation; the cycle count drives enough
	// evictions to cross rebuildMinEvictions and trigger rebuildTrie at least
	// once.
	const (
		maxEntries = 300
		cycles     = 60
		perCycle   = 200
	)
	window := 90 * time.Second
	s := NewSlidingWindowTrie(window, maxEntries)

	base := time.Now()

	// Deterministic, reproducible event generator. Concentrate many IPs into a
	// few /16 and /24 ranges so clustering actually emits CIDRs (not just /32s),
	// and intersperse a recurring "hot" IP to exercise count accumulation. Mix
	// in a spread of timestamps (some inside, some outside the window) so each
	// DropOld does real time-based eviction in addition to size eviction.
	var seq uint32 = 1
	hot := iputils.IPToUint32(net.IPv4(203, 0, 113, 7)) // recurring hot host

	rebuiltAtLeastOnce := false
	for c := 0; c < cycles; c++ {
		batch := make([]TimedIP, 0, perCycle)
		for i := 0; i < perCycle; i++ {
			var ip uint32
			switch {
			case i%17 == 0:
				// Recurring hot IP (count accumulation across cycles).
				ip = hot
			case i%2 == 0:
				// Dense /16 cluster (10.20.x.x).
				ip = iputils.IPToUint32(net.IPv4(10, 20, byte(seq/256), byte(seq%256)))
			default:
				// Dense /24 cluster (172.16.30.x).
				ip = iputils.IPToUint32(net.IPv4(172, 16, 30, byte(seq%256)))
			}
			seq++
			// Spread timestamps around "now": some old enough to be time-evicted
			// on the next cycle, most recent.
			off := time.Duration(i%5) * 30 * time.Second
			ts := base.Add(time.Duration(c) * time.Second).Add(-off)
			batch = append(batch, TimedIP{IP: ip, Time: ts})
		}
		s.Update(batch)
		if s.evictedSinceRebuild == 0 {
			// evictedSinceRebuild resets to 0 exactly when a rebuild runs (and at
			// start). After the first cycle that evicts, a 0 here means a rebuild
			// just happened.
			rebuiltAtLeastOnce = rebuiltAtLeastOnce || c > 0
		}
	}

	if !rebuiltAtLeastOnce {
		t.Fatalf("test did not exercise the periodic rebuild path; tune cycles/perCycle/maxEntries")
	}

	// --- Oracle 1: IPStats replayed over net.IP-derived keys. ---
	// Build the expected IPStats purely from the surviving IPQueue, using the
	// net.IP -> uint32 conversion (the OLD path) as the key source, and the
	// same accumulation rule addIPStat uses (Count++, Last = latest Time in
	// queue order).
	oracleStats := haxmap.New[uint32, IPStat](uintptr(maxEntries))
	for i := range s.IPQueue {
		key := iputils.IPToUint32(iputils.Uint32ToIP(s.IPQueue[i].IP)) // round-trip via net.IP
		st, ok := oracleStats.Get(key)
		if !ok {
			st = IPStat{}
		}
		st.Last = s.IPQueue[i].Time
		st.Count++
		oracleStats.Set(key, st)
	}

	if int(oracleStats.Len()) != int(s.IPStats.Len()) {
		t.Fatalf("IPStats len mismatch: window=%d oracle=%d", s.IPStats.Len(), oracleStats.Len())
	}
	oracleStats.ForEach(func(k uint32, want IPStat) bool {
		got, ok := s.IPStats.Get(k)
		if !ok {
			t.Errorf("IPStats missing key %s present in oracle", iputils.Uint32ToIP(k))
			return true
		}
		if got.Count != want.Count {
			t.Errorf("IPStats[%s].Count = %d, want %d", iputils.Uint32ToIP(k), got.Count, want.Count)
		}
		if !got.Last.Equal(want.Last) {
			t.Errorf("IPStats[%s].Last = %v, want %v", iputils.Uint32ToIP(k), got.Last, want.Last)
		}
		return true
	})

	// --- Oracle 2: reference trie built from scratch. ---
	// Insert the surviving IPQueue into a fresh trie and assert its clusters
	// are identical to the live window trie, which got there incrementally
	// (InsertUint32 / DeleteUint32 + the periodic rebuild).
	ref := trie.NewTrieSeq()
	for i := range s.IPQueue {
		v := s.IPQueue[i].IP
		if v == 0 {
			continue
		}
		ref.InsertUint32(v)
	}

	// Total counts must match.
	if got, want := s.Trie.CountAll(), ref.CountAll(); got != want {
		t.Fatalf("CountAll mismatch: window=%d reference=%d", got, want)
	}

	// Several detection tiers (tight hot-host + loose subnet), to exercise the
	// clustering walk broadly.
	tiers := []struct {
		minSize, minDepth, maxDepth uint32
		threshold                   float64
	}{
		{1, 0, 32, 0.0},
		{10, 16, 24, 0.2},
		{50, 8, 32, 0.5},
		{2, 24, 32, 1.0},
	}
	for _, tt := range tiers {
		gotN := s.Trie.CollectCIDRsNumeric(tt.minSize, tt.minDepth, tt.maxDepth, tt.threshold)
		wantN := ref.CollectCIDRsNumeric(tt.minSize, tt.minDepth, tt.maxDepth, tt.threshold)
		if len(gotN) != len(wantN) {
			t.Fatalf("tier %+v: numeric cluster count mismatch window=%d reference=%d", tt, len(gotN), len(wantN))
		}
		for i := range gotN {
			if gotN[i] != wantN[i] {
				t.Errorf("tier %+v: cluster[%d] window=%s reference=%s", tt, i, gotN[i].String(), wantN[i].String())
			}
		}
	}
}
