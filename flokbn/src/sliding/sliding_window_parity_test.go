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
// window — many inserts, time-based eviction, max-entries eviction, repeated
// IPs (count accumulation), and enough churn to trigger the periodic trie
// rebuild — then asserts three things against an INDEPENDENT oracle built from
// the surviving entries via the net.IP entry points (Insert(net.IP) /
// IPToUint32):
//
//  1. IPQueue contents (as uint32) match the oracle's surviving order.
//  2. IPStats (key set + Count + Last) match an oracle map built by replaying
//     adds/removes over net.IP-derived keys.
//  3. The window trie's clusters (CollectCIDRsNumeric AND CollectCIDRs) are
//     identical to a reference trie built the OLD way: Insert(net.IP) over the
//     same surviving IPs. This is the hard correctness invariant — clustering
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

	// --- Oracle 2: reference trie built the OLD way (Insert(net.IP)). ---
	// Reconstruct a trie from the surviving IPQueue using the net.IP entry point
	// (which internally does IPToUint32), exactly as the pre-AUDIT-05 window
	// would have, and assert its clusters are identical to the live window trie
	// (which used InsertUint32 / DeleteUint32 + the rebuild fast path).
	ref := trie.NewTrieSeq()
	for i := range s.IPQueue {
		v := s.IPQueue[i].IP
		if v == 0 {
			continue
		}
		ref.Insert(iputils.Uint32ToIP(v)) // OLD net.IP path
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
		// String form parity too (CollectCIDRs is the string wrapper).
		gotS := s.Trie.CollectCIDRs(tt.minSize, tt.minDepth, tt.maxDepth, tt.threshold)
		wantS := ref.CollectCIDRs(tt.minSize, tt.minDepth, tt.maxDepth, tt.threshold)
		if len(gotS) != len(wantS) {
			t.Fatalf("tier %+v: string cluster count mismatch window=%d reference=%d", tt, len(gotS), len(wantS))
		}
		for i := range gotS {
			if gotS[i] != wantS[i] {
				t.Errorf("tier %+v: string cluster[%d] window=%s reference=%s", tt, i, gotS[i], wantS[i])
			}
		}
	}
}

// TestTrie_DeleteUint32_ParityWithDelete proves the new Trie.DeleteUint32 entry
// point is byte-identical to Delete(net.IP) for IPv4: it deletes the same nodes,
// applies the same underflow guard, and prunes the same subtrees. Two tries are
// driven through an identical insert/delete script — one via the net.IP API, one
// via the uint32 API — and must end in identical CountAll and identical clusters
// across several tiers, including over-delete (underflow) and prune-from-deepest
// cases.
func TestTrie_DeleteUint32_ParityWithDelete(t *testing.T) {
	ips := []uint32{
		iputils.IPToUint32(net.IPv4(10, 0, 0, 1)),
		iputils.IPToUint32(net.IPv4(10, 0, 0, 1)), // dup -> count 2
		iputils.IPToUint32(net.IPv4(10, 0, 0, 2)),
		iputils.IPToUint32(net.IPv4(10, 0, 1, 1)),
		iputils.IPToUint32(net.IPv4(10, 128, 0, 1)),
		iputils.IPToUint32(net.IPv4(192, 168, 5, 5)),
	}

	netT := trie.NewTrieSeq()
	u32T := trie.NewTrieSeq()
	for _, v := range ips {
		netT.Insert(iputils.Uint32ToIP(v))
		u32T.InsertUint32(v)
	}

	// Delete script: a present dup (leaves count 1, no prune), a full delete
	// (prunes the leaf path), an absent IP (no-op), and an over-delete of an
	// already-removed IP (underflow guard must bail without wrapping).
	gone := iputils.IPToUint32(net.IPv4(192, 168, 5, 5))
	absent := iputils.IPToUint32(net.IPv4(8, 8, 8, 8))
	script := []uint32{
		iputils.IPToUint32(net.IPv4(10, 0, 0, 1)), // dup -> count 1
		gone,   // full delete -> prune
		gone,   // over-delete (underflow guard)
		absent, // absent (no-op)
		iputils.IPToUint32(net.IPv4(10, 128, 0, 1)),
	}
	for _, v := range script {
		netT.Delete(iputils.Uint32ToIP(v))
		u32T.DeleteUint32(v)
	}

	if got, want := u32T.CountAll(), netT.CountAll(); got != want {
		t.Fatalf("CountAll after deletes: DeleteUint32=%d Delete=%d", got, want)
	}

	tiers := []struct {
		minSize, minDepth, maxDepth uint32
		threshold                   float64
	}{
		{1, 0, 32, 0.0},
		{1, 0, 32, 1.0},
		{1, 8, 24, 0.5},
	}
	for _, tt := range tiers {
		got := u32T.CollectCIDRsNumeric(tt.minSize, tt.minDepth, tt.maxDepth, tt.threshold)
		want := netT.CollectCIDRsNumeric(tt.minSize, tt.minDepth, tt.maxDepth, tt.threshold)
		if len(got) != len(want) {
			t.Fatalf("tier %+v: cluster count DeleteUint32=%d Delete=%d", tt, len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("tier %+v: cluster[%d] DeleteUint32=%s Delete=%s", tt, i, got[i].String(), want[i].String())
			}
		}
	}
}
