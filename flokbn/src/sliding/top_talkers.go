package sliding

import (
	"container/heap"
	"sort"

	"github.com/ChristianF88/flokbn/iputils"
)

// TopTalker is one IP with its current request count in the window.
type TopTalker struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

type talkerEntry struct {
	ip    uint32
	count int
}

// talkerHeap is a min-heap by count. Ties order by descending IP so the
// retained set (and therefore TopTalkers' output) is deterministic:
// equal-count entries with numerically smaller IPs win.
type talkerHeap []talkerEntry

func (h talkerHeap) Len() int { return len(h) }
func (h talkerHeap) Less(i, j int) bool {
	if h[i].count != h[j].count {
		return h[i].count < h[j].count
	}
	return h[i].ip > h[j].ip
}
func (h talkerHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *talkerHeap) Push(x any)   { *h = append(*h, x.(talkerEntry)) }
func (h *talkerHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// TopTalkers returns the n highest-Count IPs currently tracked in the
// window's IPStats, sorted by descending count (ascending IP on ties).
// The scan is bounded: O(unique IPs) comparisons with a size-n min-heap,
// so memory stays O(n) regardless of window size.
func (s *SlidingWindow) TopTalkers(n int) []TopTalker {
	if n <= 0 {
		return nil
	}
	h := make(talkerHeap, 0, n)
	s.IPStats.ForEach(func(ip uint32, stat IPStat) bool {
		if len(h) < n {
			heap.Push(&h, talkerEntry{ip: ip, count: stat.Count})
		} else if top := h[0]; stat.Count > top.count || (stat.Count == top.count && ip < top.ip) {
			h[0] = talkerEntry{ip: ip, count: stat.Count}
			heap.Fix(&h, 0)
		}
		return true
	})
	sort.Slice(h, func(i, j int) bool {
		if h[i].count != h[j].count {
			return h[i].count > h[j].count
		}
		return h[i].ip < h[j].ip
	})
	out := make([]TopTalker, len(h))
	for i, e := range h {
		out[i] = TopTalker{IP: iputils.Uint32ToIP(e.ip).String(), Count: e.count}
	}
	return out
}
