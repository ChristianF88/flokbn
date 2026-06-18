package sliding

import (
	"time"

	"github.com/ChristianF88/flokbn/iputils"
	"github.com/ChristianF88/flokbn/trie"
	"github.com/alphadose/haxmap"
)

// --- Sliding Window Wrapper ---

// TimedIP carries the IP as a uint32 (the already-validated IPv4 value), not a
// net.IP. The byte form was only ever re-decoded to uint32 on every window op
// (trie Insert/Delete, IPStats key) and built per accepted request via a
// net.IPv4 heap allocation; storing uint32 removes that allocation and every
// IPToUint32 round-trip (AUDIT-05). IPv4-only is preserved upstream: the live
// loop populates this from msg.IPUint32, which is rejected/zeroed for IPv6.
type TimedIP struct {
	IP   uint32
	Time time.Time
}

type IPStat struct {
	Last  time.Time
	Count int
}

type SlidingWindow struct {
	Trie       *trie.Trie
	IPQueue    []TimedIP
	IPStats    *haxmap.Map[uint32, IPStat] // ip represented as uint32 (IPv4)
	timeLimit  time.Duration
	maxEntries int

	// evictedSinceRebuild tracks how many entries have been Delete-evicted
	// from the trie since the last full rebuild. It drives the periodic
	// rebuild that bounds RSS to window size (see DropOld).
	evictedSinceRebuild int
}

func NewSlidingWindowTrie(window time.Duration, maxEntries int) *SlidingWindow {
	return &SlidingWindow{
		// Seq-backed (lock-free) trie: the live loop and all trie access run
		// on a single goroutine, so the never-contended NodeAllocator mutex is
		// dropped from the live path. RSS is bounded by periodically rebuilding
		// the trie from the surviving IPQueue in DropOld (the old allocator's
		// chunks then become unreferenced and GC reclaims the whole generation).
		Trie:       trie.NewTrieSeq(),
		IPQueue:    make([]TimedIP, 0),
		IPStats:    haxmap.New[uint32, IPStat](1 << 21), // ~2M initial buckets (size hint)
		timeLimit:  window,
		maxEntries: maxEntries,
	}
}

// rebuildTrie reconstructs the window trie from scratch on a fresh
// SeqNodeAllocator using the SURVIVING IPQueue, then swaps it in. The previous
// trie (and its allocator chunks) becomes unreferenced so the GC reclaims the
// entire prior generation — this is what keeps RSS tracking window size rather
// than distinct-IPs-ever-seen. Uses the same RadixSort + BuildSorted fast path
// as the static build, and excludes the 0 uint32 failed-parse sentinel exactly
// as the static path does (IPv4-only).
func (s *SlidingWindow) rebuildTrie() {
	fresh := trie.NewTrieSeq()
	if len(s.IPQueue) > 0 {
		ips := make([]uint32, 0, len(s.IPQueue))
		for i := range s.IPQueue {
			v := s.IPQueue[i].IP
			// Keep the 0 skip as defense-in-depth: the failed-parse / non-IPv4
			// sentinel (uint32 0) must stay excluded from the trie, exactly as
			// the static path excludes it, so clusters are byte-identical. The
			// live loop already filters IPUint32==0 (cli/api.go), so this is
			// belt-and-suspenders.
			if v == 0 {
				continue
			}
			ips = append(ips, v)
		}
		iputils.RadixSortUint32(ips)
		fresh.BuildSorted(ips)
	}
	s.Trie = fresh
	s.evictedSinceRebuild = 0
}

func addIPStat(m *haxmap.Map[uint32, IPStat], ip uint32, timedIP TimedIP) {
	stat, exists := m.Get(ip)
	if !exists {
		stat = IPStat{
			Last:  timedIP.Time,
			Count: 0,
		}
	}
	stat.Last = timedIP.Time
	stat.Count++
	m.Set(ip, stat)
}

func removeIPStat(m *haxmap.Map[uint32, IPStat], ip uint32) {
	stat, exists := m.Get(ip)
	if !exists {
		return
	}
	stat.Count--
	if stat.Count <= 0 {
		m.Del(ip)
		return
	}
	m.Set(ip, stat)
}

func (s *SlidingWindow) InsertNew(timedIPs []TimedIP) {
	s.IPQueue = append(s.IPQueue, timedIPs...)
	for _, timedIP := range timedIPs {
		s.Trie.InsertUint32(timedIP.IP)
		addIPStat(s.IPStats, timedIP.IP, timedIP)
	}
}

// rebuildMinEvictions is the floor on accumulated evictions before a periodic
// rebuild is even considered. It keeps small / lightly-churning windows from
// rebuilding every tick (rebuild cost would dominate), while still bounding RSS
// for busy windows via the relative threshold below.
const rebuildMinEvictions = 1024

func (s *SlidingWindow) DropOld() {
	// enforce time limit
	cutoff := time.Now().Add(-s.timeLimit)
	idxTime := 0
	for idxTime < len(s.IPQueue) && s.IPQueue[idxTime].Time.Before(cutoff) {
		s.Trie.DeleteUint32(s.IPQueue[idxTime].IP)
		removeIPStat(s.IPStats, s.IPQueue[idxTime].IP)
		idxTime++
	}
	// enforce max entries
	remainingLen := len(s.IPQueue) - idxTime
	if remainingLen > s.maxEntries {
		toDelete := remainingLen - s.maxEntries
		for idxLen := 0; idxLen < toDelete; idxLen++ {
			s.Trie.DeleteUint32(s.IPQueue[idxTime+idxLen].IP)
			removeIPStat(s.IPStats, s.IPQueue[idxTime+idxLen].IP)
		}
		idxTime += toDelete
	}

	if idxTime > 0 {
		// Efficient memory-releasing slice copy
		s.IPQueue = append([]TimedIP(nil), s.IPQueue[idxTime:]...)
		s.evictedSinceRebuild += idxTime
	}

	// Periodic rebuild bounds RSS to window size. Delete only detaches node
	// references; the Seq allocator's backing chunks stay resident until the
	// whole trie is dropped, so without this the chunks would grow with
	// distinct-IPs-ever-seen. Only rebuild when evictions have actually
	// accumulated dead capacity: at least rebuildMinEvictions evictions AND at
	// least as many evictions as the surviving window size (so a steady-state
	// window of N rebuilds roughly once per N evictions, i.e. amortized O(1)
	// extra work per evicted entry).
	remaining := len(s.IPQueue)
	if s.evictedSinceRebuild >= rebuildMinEvictions && s.evictedSinceRebuild >= remaining {
		s.rebuildTrie()
	}
}

func (s *SlidingWindow) Update(timedIPs []TimedIP) {
	s.InsertNew(timedIPs)
	s.DropOld()
}
