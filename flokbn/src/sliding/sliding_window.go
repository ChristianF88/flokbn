package sliding

import (
	"net"
	"time"

	"github.com/ChristianF88/flokbn/iputils"
	"github.com/ChristianF88/flokbn/trie"
	"github.com/alphadose/haxmap"
)

// --- Sliding Window Wrapper ---

type TimedIP struct {
	IP   net.IP
	Time time.Time
}

type IPStat struct {
	Last   time.Time
	DeltaT []time.Duration
	Count  int
}

type SlidingWindow struct {
	Trie       *trie.Trie
	IPQueue    []TimedIP
	IPStats    *haxmap.Map[uint32, IPStat] // ip represented as uint32 (IPv4)
	timeLimit  time.Duration
	maxEntries int
}

func NewSlidingWindowTrie(window time.Duration, maxEntries int) *SlidingWindow {
	return &SlidingWindow{
		Trie:       trie.NewTrie(),
		IPQueue:    make([]TimedIP, 0),
		IPStats:    haxmap.New[uint32, IPStat](1 << 21), // 256M entries preallocated
		timeLimit:  window,
		maxEntries: maxEntries,
	}
}

func addIPStat(m *haxmap.Map[uint32, IPStat], ip net.IP, timedIP TimedIP) {
	var skipDeltaT bool = false
	ipUint32 := iputils.IPToUint32(ip)
	stat, exists := m.Get(ipUint32)
	if !exists {
		stat = IPStat{
			Last:   timedIP.Time,
			DeltaT: make([]time.Duration, 0),
			Count:  0,
		}
		skipDeltaT = true
	}

	if !skipDeltaT {
		stat.DeltaT = append(stat.DeltaT, timedIP.Time.Sub(stat.Last))
	}
	stat.Last = timedIP.Time
	stat.Count++
	m.Set(ipUint32, stat)
}

func removeIPStat(m *haxmap.Map[uint32, IPStat], ip net.IP) {
	ipUint32 := iputils.IPToUint32(ip)
	stat, exists := m.Get(ipUint32)
	if !exists {
		return
	}
	stat.Count--
	if stat.Count <= 0 {
		m.Del(ipUint32)
		return
	}
	// Remove the first element from DeltaT
	if len(stat.DeltaT) > 0 {
		stat.DeltaT = stat.DeltaT[1:]
	}
	m.Set(ipUint32, stat)
}

func (s *SlidingWindow) InsertNew(timedIPs []TimedIP) {
	s.IPQueue = append(s.IPQueue, timedIPs...)
	for _, timedIP := range timedIPs {
		s.Trie.Insert(timedIP.IP)
		addIPStat(s.IPStats, timedIP.IP, timedIP)
	}
}

func (s *SlidingWindow) DropOld() {
	// enforce time limit
	cutoff := time.Now().Add(-s.timeLimit)
	idxTime := 0
	for idxTime < len(s.IPQueue) && s.IPQueue[idxTime].Time.Before(cutoff) {
		s.Trie.Delete(s.IPQueue[idxTime].IP)
		removeIPStat(s.IPStats, s.IPQueue[idxTime].IP)
		idxTime++
	}
	// enforce max entries
	remainingLen := len(s.IPQueue) - idxTime
	if remainingLen > s.maxEntries {
		toDelete := remainingLen - s.maxEntries
		for idxLen := 0; idxLen < toDelete; idxLen++ {
			s.Trie.Delete(s.IPQueue[idxTime+idxLen].IP)
			removeIPStat(s.IPStats, s.IPQueue[idxTime+idxLen].IP)
		}
		idxTime += toDelete
	}

	if idxTime > 0 {
		// Efficient memory-releasing slice copy
		s.IPQueue = append([]TimedIP(nil), s.IPQueue[idxTime:]...)
	}
}

func (s *SlidingWindow) Update(timedIPs []TimedIP) {
	s.InsertNew(timedIPs)
	s.DropOld()
}
