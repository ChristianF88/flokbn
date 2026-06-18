package sliding

import (
	"net"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/iputils"
	"github.com/ChristianF88/flokbn/trie"
	"github.com/alphadose/haxmap"
)

func TestSlidingWindowTrieInsert(t *testing.T) {
	tests := []struct {
		name          string
		timedIPs      []TimedIP
		expectedCount uint32
	}{
		{
			name: "Insert single IP",
			timedIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now()},
			},
			expectedCount: 1,
		},
		{
			name: "Insert multiple unique IPs",
			timedIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now()},
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.2")), Time: time.Now()},
			},
			expectedCount: 2,
		},
		{
			name: "Insert duplicate IPs",
			timedIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now()},
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now()},
			},
			expectedCount: 2,
		},
		{
			name:          "Insert no IPs",
			timedIPs:      []TimedIP{},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize a new SlidingWindowTrie
			window := 10 * time.Second
			maxEntries := 5
			swt := NewSlidingWindowTrie(window, maxEntries)

			// Insert timed IPs
			swt.InsertNew(tt.timedIPs)

			// Verify the total count of IPs in the Trie
			totalCount := swt.Trie.CountAll()
			if totalCount != tt.expectedCount {
				t.Errorf("Expected total count %d, got %d", tt.expectedCount, totalCount)
			}

			// Verify the IPs are in the queue
			if len(swt.IPQueue) != len(tt.timedIPs) {
				t.Errorf("Expected queue length %d, got %d", len(tt.timedIPs), len(swt.IPQueue))
			}
		})
	}
}
func TestSlidingWindowTrieCleanup(t *testing.T) {
	tests := []struct {
		name          string
		timedIPs      []TimedIP
		timeLimit     time.Duration
		maxEntries    int
		expectedCount uint32
	}{
		{
			name: "Cleanup removes expired IPs",
			timedIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now().Add(-15 * time.Second)},
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.2")), Time: time.Now().Add(-5 * time.Second)},
			},
			timeLimit:     10 * time.Second,
			maxEntries:    5,
			expectedCount: 1,
		},
		{
			name: "Cleanup keeps all IPs within time limit",
			timedIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now().Add(-5 * time.Second)},
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.2")), Time: time.Now().Add(-3 * time.Second)},
			},
			timeLimit:     10 * time.Second,
			maxEntries:    5,
			expectedCount: 2,
		},
		{
			name: "Cleanup removes all IPs when all are expired",
			timedIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now().Add(-15 * time.Second)},
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.2")), Time: time.Now().Add(-12 * time.Second)},
			},
			timeLimit:     10 * time.Second,
			maxEntries:    5,
			expectedCount: 0,
		},
		{
			name:          "Cleanup with no IPs",
			timedIPs:      []TimedIP{},
			timeLimit:     10 * time.Second,
			maxEntries:    5,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize a new SlidingWindowTrie
			swt := NewSlidingWindowTrie(tt.timeLimit, tt.maxEntries)

			// Insert timed IPs
			swt.InsertNew(tt.timedIPs)

			// Perform cleanup
			swt.DropOld()

			// Verify the total count of IPs in the Trie
			totalCount := swt.Trie.CountAll()
			if totalCount != tt.expectedCount {
				t.Errorf("Expected total count %d, got %d", tt.expectedCount, totalCount)
			}

			// Verify the IPs in the queue
			if len(swt.IPQueue) != int(tt.expectedCount) {
				t.Errorf("Expected queue length %d, got %d", tt.expectedCount, len(swt.IPQueue))
			}
		})
	}
}
func TestSlidingWindowTrieUpdate(t *testing.T) {
	tests := []struct {
		name          string
		initialIPs    []TimedIP
		newIPs        []TimedIP
		timeLimit     time.Duration
		maxEntries    int
		expectedCount uint32
	}{
		{
			name: "Update adds new IPs and removes expired ones",
			initialIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now().Add(-15 * time.Second)},
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.2")), Time: time.Now().Add(-5 * time.Second)},
			},
			newIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.3")), Time: time.Now()},
			},
			timeLimit:     10 * time.Second,
			maxEntries:    5,
			expectedCount: 2,
		},
		{
			name: "Update keeps all valid IPs and adds new ones",
			initialIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now().Add(-5 * time.Second)},
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.2")), Time: time.Now().Add(-3 * time.Second)},
			},
			newIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.3")), Time: time.Now()},
			},
			timeLimit:     10 * time.Second,
			maxEntries:    5,
			expectedCount: 3,
		},
		{
			name: "Update removes all expired IPs and adds new ones",
			initialIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now().Add(-15 * time.Second)},
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.2")), Time: time.Now().Add(-12 * time.Second)},
			},
			newIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.3")), Time: time.Now()},
			},
			timeLimit:     10 * time.Second,
			maxEntries:    5,
			expectedCount: 1,
		},
		{
			name:          "Update with no initial or new IPs",
			initialIPs:    []TimedIP{},
			newIPs:        []TimedIP{},
			timeLimit:     10 * time.Second,
			maxEntries:    5,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize a new SlidingWindowTrie
			swt := NewSlidingWindowTrie(tt.timeLimit, tt.maxEntries)

			// Insert initial IPs
			swt.InsertNew(tt.initialIPs)

			// Call Move with new IPs
			swt.Update(tt.newIPs)

			// Verify the total count of IPs in the Trie
			totalCount := swt.Trie.CountAll()
			if totalCount != tt.expectedCount {
				t.Errorf("Expected total count %d, got %d", tt.expectedCount, totalCount)
			}

			// Verify the IPs in the queue
			if len(swt.IPQueue) != int(tt.expectedCount) {
				t.Errorf("Expected queue length %d, got %d", tt.expectedCount, len(swt.IPQueue))
			}
		})
	}
}
func TestSlidingWindowTrieUpdateOnlyInsert(t *testing.T) {
	tests := []struct {
		name          string
		newIPs        []TimedIP
		timeLimit     time.Duration
		maxEntries    int
		expectedCount uint32
	}{
		{
			name: "Update inserts new IPs",
			newIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now()},
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.2")), Time: time.Now()},
			},
			timeLimit:     10 * time.Second,
			maxEntries:    5,
			expectedCount: 2,
		},
		{
			name:          "Update with no IPs",
			newIPs:        []TimedIP{},
			timeLimit:     10 * time.Second,
			maxEntries:    5,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize a new SlidingWindowTrie
			swt := NewSlidingWindowTrie(tt.timeLimit, tt.maxEntries)

			// Call Update with new IPs
			swt.Update(tt.newIPs)

			// Verify the total count of IPs in the Trie
			totalCount := swt.Trie.CountAll()
			if totalCount != tt.expectedCount {
				t.Errorf("Expected total count %d, got %d", tt.expectedCount, totalCount)
			}

			// Verify the IPs in the queue
			if len(swt.IPQueue) != int(tt.expectedCount) {
				t.Errorf("Expected queue length %d, got %d", tt.expectedCount, len(swt.IPQueue))
			}
		})
	}
}

func TestSlidingWindowTrieUpdateWithDifferentLengths(t *testing.T) {
	tests := []struct {
		name          string
		initialIPs    []TimedIP
		newIPs        []TimedIP
		timeLimit     time.Duration
		maxEntries    int
		expectedCount uint32
	}{
		{
			name: "Update with more new IPs than initial",
			initialIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now().Add(-5 * time.Second)},
			},
			newIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.2")), Time: time.Now()},
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.3")), Time: time.Now()},
			},
			timeLimit:     10 * time.Second,
			maxEntries:    5,
			expectedCount: 3,
		},
		{
			name: "Update with fewer new IPs than initial",
			initialIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now().Add(-5 * time.Second)},
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.2")), Time: time.Now().Add(-3 * time.Second)},
			},
			newIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.3")), Time: time.Now()},
			},
			timeLimit:     10 * time.Second,
			maxEntries:    5,
			expectedCount: 3,
		},
		{
			name: "Update with equal number of initial and new IPs",
			initialIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now().Add(-5 * time.Second)},
			},
			newIPs: []TimedIP{
				{IP: iputils.IPToUint32(net.ParseIP("192.168.1.2")), Time: time.Now()},
			},
			timeLimit:     10 * time.Second,
			maxEntries:    5,
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize a new SlidingWindowTrie
			swt := NewSlidingWindowTrie(tt.timeLimit, tt.maxEntries)

			swt.Update(tt.initialIPs)
			swt.Update(tt.newIPs)

			// Verify the total count of IPs in the Trie
			totalCount := swt.Trie.CountAll()
			if totalCount != tt.expectedCount {
				t.Errorf("Expected total count %d, got %d", tt.expectedCount, totalCount)
			}

			// Verify the IPs in the queue
			if len(swt.IPQueue) != int(tt.expectedCount) {
				t.Errorf("Expected queue length %d, got %d", tt.expectedCount, len(swt.IPQueue))
			}
		})
	}
}

func TestSlidingWindowTrieMaxLength(t *testing.T) {
	timeIPs := []TimedIP{
		{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now().Add(-25 * time.Second)},
		{IP: iputils.IPToUint32(net.ParseIP("192.168.1.2")), Time: time.Now().Add(-20 * time.Second)},
		{IP: iputils.IPToUint32(net.ParseIP("192.168.1.3")), Time: time.Now().Add(-15 * time.Second)},
		{IP: iputils.IPToUint32(net.ParseIP("192.168.1.4")), Time: time.Now().Add(-10 * time.Second)},
		{IP: iputils.IPToUint32(net.ParseIP("192.168.1.5")), Time: time.Now().Add(-5 * time.Second)},
	}
	tests := []struct {
		name          string
		timedIPs      []TimedIP
		timeLimit     time.Duration
		maxEntries    int
		expectedCount uint32
	}{
		{
			name:          "Max entries limit is respected",
			timedIPs:      timeIPs,
			timeLimit:     120 * time.Second,
			maxEntries:    2,
			expectedCount: 2,
		},
		{
			name:          "Max entries limit with no IPs",
			timedIPs:      []TimedIP{},
			timeLimit:     10 * time.Second,
			maxEntries:    5,
			expectedCount: 0,
		},
		{
			name:          "Max entries limit with fewer IPs than max",
			timedIPs:      timeIPs,
			timeLimit:     120 * time.Second,
			maxEntries:    10,
			expectedCount: 5,
		},
		{
			name:          "Max entries limit with exactly max entries",
			timedIPs:      timeIPs,
			timeLimit:     120 * time.Second,
			maxEntries:    5,
			expectedCount: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize a new SlidingWindowTrie
			swt := NewSlidingWindowTrie(tt.timeLimit, tt.maxEntries)

			// Insert timed IPs
			swt.InsertNew(tt.timedIPs)

			// Perform cleanup
			swt.DropOld()

			// Verify the total count of IPs in the Trie
			totalCount := swt.Trie.CountAll()
			if totalCount != tt.expectedCount {
				t.Errorf("Expected total count %d, got %d", tt.expectedCount, totalCount)
			}

			// Verify the IPs in the queue
			if len(swt.IPQueue) != int(tt.expectedCount) {
				t.Errorf("Expected queue length %d, got %d", tt.expectedCount, len(swt.IPQueue))
			}
		})
	}
}

func TestSlidingWindowTrieMaxLengthAndTimeLimitAreEnforced(t *testing.T) {
	timeIPs := []TimedIP{
		{IP: iputils.IPToUint32(net.ParseIP("192.168.1.1")), Time: time.Now().Add(-25 * time.Second)},
		{IP: iputils.IPToUint32(net.ParseIP("192.168.1.2")), Time: time.Now().Add(-20 * time.Second)},
		{IP: iputils.IPToUint32(net.ParseIP("192.168.1.3")), Time: time.Now().Add(-15 * time.Second)},
		{IP: iputils.IPToUint32(net.ParseIP("192.168.1.4")), Time: time.Now().Add(-10 * time.Second)},
		{IP: iputils.IPToUint32(net.ParseIP("192.168.1.5")), Time: time.Now().Add(-5 * time.Second)},
	}
	tests := []struct {
		name          string
		timedIPs      []TimedIP
		timeLimit     time.Duration
		maxEntries    int
		expectedCount uint32
	}{
		{
			name:          "Time limit is enforced",
			timedIPs:      timeIPs,
			timeLimit:     12 * time.Second,
			maxEntries:    5,
			expectedCount: 2,
		},
		{
			name:          "Time limit with no IPs",
			timedIPs:      []TimedIP{},
			timeLimit:     12 * time.Second,
			maxEntries:    3,
			expectedCount: 0,
		},

		{
			name:          "Max entries is enforced",
			timedIPs:      timeIPs,
			timeLimit:     120 * time.Second,
			maxEntries:    2,
			expectedCount: 2,
		},
		{
			name:          "Max entries with no IPs",
			timedIPs:      []TimedIP{},
			timeLimit:     120 * time.Second,
			maxEntries:    5,
			expectedCount: 0,
		},
		{
			name:          "Both are enforced, first by time limit then by max entries",
			timedIPs:      timeIPs,
			timeLimit:     12 * time.Second,
			maxEntries:    1,
			expectedCount: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize a new SlidingWindowTrie
			swt := NewSlidingWindowTrie(tt.timeLimit, tt.maxEntries)

			// Insert timed IPs and Cleanup
			swt.Update(tt.timedIPs)

			// Verify the total count of IPs in the Trie
			totalCount := swt.Trie.CountAll()
			if totalCount != tt.expectedCount {
				t.Errorf("Expected total count %d, got %d", tt.expectedCount, totalCount)
			}

			// Verify the IPs in the queue
			if len(swt.IPQueue) != int(tt.expectedCount) {
				t.Errorf("Expected queue length %d, got %d", tt.expectedCount, len(swt.IPQueue))
			}
		})
	}
}
func TestAddIPStat(t *testing.T) {
	now := time.Now()
	ip1 := iputils.IPToUint32(net.ParseIP("192.168.1.1"))
	ip2 := iputils.IPToUint32(net.ParseIP("192.168.1.2"))

	t.Run("Insert new IP", func(t *testing.T) {
		m := haxmap.New[uint32, IPStat](8)
		ti := TimedIP{
			IP:   ip1,
			Time: now,
		}
		addIPStat(m, ip1, ti)
		ipUint32 := ip1
		stat, exists := m.Get(ipUint32)
		if !exists {
			t.Fatalf("Expected IP stat to exist after insert")
		}
		if stat.Count != 1 {
			t.Errorf("Expected count 1, got %d", stat.Count)
		}
		if stat.Last != now {
			t.Errorf("Expected Last to be %v, got %v", now, stat.Last)
		}
	})

	t.Run("Insert same IP again, count and Last update", func(t *testing.T) {
		m := haxmap.New[uint32, IPStat](8)
		ti1 := TimedIP{
			IP:   ip1,
			Time: now,
		}
		ti2 := TimedIP{
			IP:   ip1,
			Time: now.Add(2 * time.Second),
		}
		addIPStat(m, ip1, ti1)
		addIPStat(m, ip1, ti2)
		ipUint32 := ip1
		stat, exists := m.Get(ipUint32)
		if !exists {
			t.Fatalf("Expected IP stat to exist after insert")
		}
		if stat.Count != 2 {
			t.Errorf("Expected count 2, got %d", stat.Count)
		}
		if stat.Last != now.Add(2*time.Second) {
			t.Errorf("Expected Last to be %v, got %v", now.Add(2*time.Second), stat.Last)
		}
	})

	t.Run("Insert multiple different IPs", func(t *testing.T) {
		m := haxmap.New[uint32, IPStat](8)
		ti1 := TimedIP{
			IP:   ip1,
			Time: now,
		}
		ti2 := TimedIP{
			IP:   ip2,
			Time: now.Add(1 * time.Second),
		}
		addIPStat(m, ip1, ti1)
		addIPStat(m, ip2, ti2)
		if _, exists := m.Get(ip1); !exists {
			t.Errorf("Expected ip1 to exist in map")
		}
		if _, exists := m.Get(ip2); !exists {
			t.Errorf("Expected ip2 to exist in map")
		}
	})
}
func TestRemoveIPStat(t *testing.T) {
	now := time.Now()
	ip1 := iputils.IPToUint32(net.ParseIP("192.168.1.1"))
	ip2 := iputils.IPToUint32(net.ParseIP("192.168.1.2"))

	t.Run("Delete from empty map does nothing", func(t *testing.T) {
		m := haxmap.New[uint32, IPStat](8)
		removeIPStat(m, ip1)
		if _, exists := m.Get(ip1); exists {
			t.Errorf("Expected ip1 to not exist in map")
		}
	})

	t.Run("Delete single entry removes from map", func(t *testing.T) {
		m := haxmap.New[uint32, IPStat](8)
		stat := IPStat{
			Last:  now,
			Count: 1,
		}
		m.Set(ip1, stat)
		removeIPStat(m, ip1)
		if _, exists := m.Get(ip1); exists {
			t.Errorf("Expected ip1 to be deleted from map")
		}
	})

	t.Run("Delete decrements count for multiple entries", func(t *testing.T) {
		m := haxmap.New[uint32, IPStat](8)
		stat := IPStat{
			Last:  now,
			Count: 3,
		}
		m.Set(ip1, stat)
		removeIPStat(m, ip1)
		got, exists := m.Get(ip1)
		if !exists {
			t.Fatalf("Expected ip1 to still exist in map")
		}
		if got.Count != 2 {
			t.Errorf("Expected count 2, got %d", got.Count)
		}
	})

	t.Run("Delete when count becomes zero removes entry", func(t *testing.T) {
		m := haxmap.New[uint32, IPStat](8)
		stat := IPStat{
			Last:  now,
			Count: 1,
		}
		m.Set(ip1, stat)
		removeIPStat(m, ip1)
		if _, exists := m.Get(ip1); exists {
			t.Errorf("Expected ip1 to be deleted from map")
		}
	})

	t.Run("Delete handles multiple IPs independently", func(t *testing.T) {
		m := haxmap.New[uint32, IPStat](8)
		stat1 := IPStat{
			Last:  now,
			Count: 1,
		}
		stat2 := IPStat{
			Last:  now,
			Count: 1,
		}
		m.Set(ip1, stat1)
		m.Set(ip2, stat2)
		removeIPStat(m, ip1)
		if _, exists := m.Get(ip1); exists {
			t.Errorf("Expected ip1 to be deleted from map")
		}
		if _, exists := m.Get(ip2); !exists {
			t.Errorf("Expected ip2 to still exist in map")
		}
	})
}
func TestRemoveIPStat_DecrementKeepsEntry(t *testing.T) {
	// Verify that removeIPStat decrements the count and keeps the entry when
	// the count stays above zero.
	m := haxmap.New[uint32, IPStat](8)
	ipUint32 := iputils.IPToUint32(net.ParseIP("10.0.0.1"))

	stat := IPStat{
		Last:  time.Now(),
		Count: 2,
	}
	m.Set(ipUint32, stat)

	removeIPStat(m, ipUint32)

	got, exists := m.Get(ipUint32)
	if !exists {
		t.Fatalf("Expected IP stat to still exist after decrement")
	}
	if got.Count != 1 {
		t.Errorf("Expected count 1, got %d", got.Count)
	}
}

func TestSlidingWindow_Update(t *testing.T) {
	now := time.Now()
	ip1 := iputils.IPToUint32(net.ParseIP("192.168.1.1"))
	ip2 := iputils.IPToUint32(net.ParseIP("192.168.1.2"))
	ip3 := iputils.IPToUint32(net.ParseIP("192.168.1.3"))

	t.Run("Update inserts new IPs and drops none if within window and maxEntries", func(t *testing.T) {
		s := NewSlidingWindowTrie(10*time.Second, 10)
		ti1 := TimedIP{IP: ip1, Time: now}
		ti2 := TimedIP{IP: ip2, Time: now.Add(1 * time.Second)}
		s.Update([]TimedIP{ti1, ti2})

		if s.Trie.CountAll() != 2 {
			t.Errorf("Expected 2 IPs in trie, got %d", s.Trie.CountAll())
		}
		if len(s.IPQueue) != 2 {
			t.Errorf("Expected 2 IPs in queue, got %d", len(s.IPQueue))
		}
		if s.IPStats.Len() != 2 {
			t.Errorf("Expected 2 IP stats, got %d", s.IPStats.Len())
		}
	})

	t.Run("Update drops old IPs outside time window", func(t *testing.T) {
		s := NewSlidingWindowTrie(2*time.Second, 10)
		old := TimedIP{IP: ip1, Time: now.Add(-5 * time.Second)}
		newer := TimedIP{IP: ip2, Time: now}
		s.InsertNew([]TimedIP{old})
		s.Update([]TimedIP{newer})

		if s.Trie.CountAll() != 1 {
			t.Errorf("Expected 1 IP in trie, got %d", s.Trie.CountAll())
		}
		if len(s.IPQueue) != 1 {
			t.Errorf("Expected 1 IP in queue, got %d", len(s.IPQueue))
		}
		if s.IPQueue[0].IP != ip2 {
			t.Errorf("Expected remaining IP to be ip2, got %v", s.IPQueue[0].IP)
		}
		if s.IPStats.Len() != 1 {
			t.Errorf("Expected 1 IP stat, got %d", s.IPStats.Len())
		}
		val, exists := s.IPStats.Get(ip2)
		if !exists {
			t.Fatalf("Expected ip2 to exist in stats")
		}
		if val.Count != 1 {
			t.Errorf("Expected ip2 count to be 1, got %d", val.Count)
		}
	})

	t.Run("Update enforces maxEntries", func(t *testing.T) {
		s := NewSlidingWindowTrie(10*time.Second, 2)
		ti1 := TimedIP{IP: ip1, Time: now}
		ti2 := TimedIP{IP: ip2, Time: now.Add(1 * time.Second)}
		ti3 := TimedIP{IP: ip3, Time: now.Add(2 * time.Second)}
		s.Update([]TimedIP{ti1, ti2, ti3})

		if s.Trie.CountAll() != 2 {
			t.Errorf("Expected 2 IPs in trie, got %d", s.Trie.CountAll())
		}
		if len(s.IPQueue) != 2 {
			t.Errorf("Expected 2 IPs in queue, got %d", len(s.IPQueue))
		}
		// Should keep the last two inserted
		if s.IPQueue[0].IP != ip2 || s.IPQueue[1].IP != ip3 {
			t.Errorf("Expected queue to have ip2 and ip3, got %v and %v", s.IPQueue[0].IP, s.IPQueue[1].IP)
		}
	})

	t.Run("Update with empty input does not change state", func(t *testing.T) {
		s := NewSlidingWindowTrie(10*time.Second, 5)
		ti1 := TimedIP{IP: ip1, Time: now}
		s.InsertNew([]TimedIP{ti1})
		s.Update([]TimedIP{})

		if s.Trie.CountAll() != 1 {
			t.Errorf("Expected 1 IP in trie, got %d", s.Trie.CountAll())
		}
		if len(s.IPQueue) != 1 {
			t.Errorf("Expected 1 IP in queue, got %d", len(s.IPQueue))
		}
		val, exists := s.IPStats.Get(ip1)
		if !exists {
			t.Fatalf("Expected ip1 to exist in stats")
		}
		if val.Count != 1 {
			t.Errorf("Expected ip1 count to be 1, got %d", val.Count)
		}
	})

	t.Run("Update with all expired IPs removes all", func(t *testing.T) {
		s := NewSlidingWindowTrie(1*time.Second, 5)
		old := TimedIP{IP: ip1, Time: now.Add(-10 * time.Second)}
		s.InsertNew([]TimedIP{old})
		s.Update([]TimedIP{})

		if s.Trie.CountAll() != 0 {
			t.Errorf("Expected 0 IPs in trie, got %d", s.Trie.CountAll())
		}
		if len(s.IPQueue) != 0 {
			t.Errorf("Expected 0 IPs in queue, got %d", len(s.IPQueue))
		}
		if s.IPStats.Len() != 0 {
			t.Errorf("Expected 0 IP stats, got %d", s.IPStats.Len())
		}
		if _, exists := s.IPStats.Get(ip1); exists {
			t.Errorf("Expected ip1 to be deleted from stats")
		}
	})
}

// TestSlidingWindow_ClusterDetection verifies that after filling the sliding
// window with IPs concentrated in a single /16, CollectCIDRs detects the cluster.
func TestSlidingWindow_ClusterDetection(t *testing.T) {
	now := time.Now()
	s := NewSlidingWindowTrie(60*time.Second, 100000)

	// Insert 5000 IPs in 10.20.0.0/16
	batch := make([]TimedIP, 5000)
	for i := range batch {
		v := i + 1
		ip := iputils.IPToUint32(net.IPv4(10, 20, byte(v/256), byte(v%256)))
		batch[i] = TimedIP{IP: ip, Time: now}
	}
	s.Update(batch)

	if s.Trie.CountAll() != 5000 {
		t.Fatalf("Expected 5000 IPs in trie, got %d", s.Trie.CountAll())
	}

	// CollectCIDRs should detect a cluster in the 10.20.x.x range
	cidrs := s.Trie.CollectCIDRs(1000, 16, 24, 0.2)
	if len(cidrs) == 0 {
		t.Fatal("Expected at least one detected cluster")
	}

	found := false
	for _, c := range cidrs {
		if len(c) >= 5 && c[:5] == "10.20" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected cluster in 10.20.x.x range, got: %v", cidrs)
	}
}

// TestSlidingWindow_EvictionByTime_Ordering verifies that time-based eviction
// removes the oldest IPs first and preserves ordering.
func TestSlidingWindow_EvictionByTime_Ordering(t *testing.T) {
	s := NewSlidingWindowTrie(5*time.Second, 100)
	now := time.Now()

	// Insert 3 IPs at different times
	ips := []TimedIP{
		{IP: iputils.IPToUint32(net.ParseIP("10.0.0.1")), Time: now.Add(-10 * time.Second)}, // expired
		{IP: iputils.IPToUint32(net.ParseIP("10.0.0.2")), Time: now.Add(-7 * time.Second)},  // expired
		{IP: iputils.IPToUint32(net.ParseIP("10.0.0.3")), Time: now.Add(-2 * time.Second)},  // active
	}
	s.InsertNew(ips)

	if len(s.IPQueue) != 3 {
		t.Fatalf("Expected 3 IPs before cleanup, got %d", len(s.IPQueue))
	}

	s.DropOld()

	if len(s.IPQueue) != 1 {
		t.Fatalf("Expected 1 IP after cleanup, got %d", len(s.IPQueue))
	}

	if s.IPQueue[0].IP != iputils.IPToUint32(net.ParseIP("10.0.0.3")) {
		t.Errorf("Expected remaining IP to be 10.0.0.3, got %v", iputils.Uint32ToIP(s.IPQueue[0].IP))
	}

	// Trie should also only have 1 entry
	if s.Trie.CountAll() != 1 {
		t.Errorf("Expected 1 IP in trie after cleanup, got %d", s.Trie.CountAll())
	}
}

// TestSlidingWindow_EvictionBySize_OldestFirst verifies that when maxEntries
// is exceeded, the oldest entries are evicted first.
func TestSlidingWindow_EvictionBySize_OldestFirst(t *testing.T) {
	s := NewSlidingWindowTrie(60*time.Second, 3) // long window, small max
	now := time.Now()

	// Insert 5 IPs (all within time window)
	ips := make([]TimedIP, 5)
	for i := range ips {
		ips[i] = TimedIP{
			IP:   iputils.IPToUint32(net.IPv4(10, 0, 0, byte(i+1))),
			Time: now.Add(time.Duration(i) * time.Second),
		}
	}
	s.Update(ips)

	// Should keep only the 3 newest
	if s.Trie.CountAll() != 3 {
		t.Errorf("Expected 3 IPs in trie, got %d", s.Trie.CountAll())
	}
	if len(s.IPQueue) != 3 {
		t.Errorf("Expected 3 IPs in queue, got %d", len(s.IPQueue))
	}

	// Verify the kept IPs are 10.0.0.3, 10.0.0.4, 10.0.0.5
	for i, qip := range s.IPQueue {
		expected := iputils.IPToUint32(net.IPv4(10, 0, 0, byte(i+3)))
		if qip.IP != expected {
			t.Errorf("Queue[%d]: expected %v, got %v", i, iputils.Uint32ToIP(expected), iputils.Uint32ToIP(qip.IP))
		}
	}
}

// TestSlidingWindow_IPStatAccumulation verifies that repeated inserts of the
// same IP correctly accumulate count.
func TestSlidingWindow_IPStatAccumulation(t *testing.T) {
	s := NewSlidingWindowTrie(60*time.Second, 100)
	now := time.Now()

	ip := iputils.IPToUint32(net.ParseIP("192.168.1.1"))
	ips := []TimedIP{
		{IP: ip, Time: now},
		{IP: ip, Time: now.Add(2 * time.Second)},
		{IP: ip, Time: now.Add(5 * time.Second)},
	}
	s.Update(ips)

	stat, exists := s.IPStats.Get(ip)
	if !exists {
		t.Fatal("Expected IP stat to exist")
	}
	if stat.Count != 3 {
		t.Errorf("Expected count 3, got %d", stat.Count)
	}
}

// countResidentTrieNodes walks the window trie and counts every node still
// referenced from the Root (excluding the Root). After Delete pruning +
// periodic rebuild, this reflects only the live window, not every distinct IP
// ever inserted.
func countResidentTrieNodes(n *trie.TrieNode) int {
	if n == nil {
		return 0
	}
	return 1 + countResidentTrieNodes(n.Children[0]) + countResidentTrieNodes(n.Children[1])
}

// TestSlidingWindowMemoryBoundedByWindow (URGENT-03) proves the live trie's
// memory tracks WINDOW SIZE, not distinct-IPs-ever-seen. It feeds many distinct
// IPs across several Update cycles with a small maxEntries so each cycle evicts
// the previous window's IPs; the resident node count, IPQueue, IPStats, and
// CountAll must all stay bounded to ~window size rather than growing with the
// total number of distinct IPs fed.
func TestSlidingWindowMemoryBoundedByWindow(t *testing.T) {
	const maxEntries = 500
	// A long time limit so eviction is driven purely by maxEntries (size),
	// keeping the test deterministic and time-independent.
	s := NewSlidingWindowTrie(time.Hour, maxEntries)

	const cycles = 40
	const perCycle = 1000 // > maxEntries so every cycle forces size eviction
	now := time.Now()

	// A fully distinct IP for every single insert across all cycles, so a
	// leaking trie would accumulate cycles*perCycle = 40,000 distinct leaves.
	var counter uint32 = 1
	nextIP := func() uint32 {
		ip := counter
		counter++
		return ip
	}

	for c := 0; c < cycles; c++ {
		batch := make([]TimedIP, 0, perCycle)
		for i := 0; i < perCycle; i++ {
			batch = append(batch, TimedIP{IP: nextIP(), Time: now})
		}
		s.Update(batch)

		// IPQueue is hard-capped at maxEntries by size eviction.
		if len(s.IPQueue) > maxEntries {
			t.Fatalf("cycle %d: IPQueue grew past maxEntries: %d > %d", c, len(s.IPQueue), maxEntries)
		}
	}

	totalDistinctFed := uint32(cycles * perCycle)

	// CountAll reflects only the live window.
	if got := s.Trie.CountAll(); got > uint32(maxEntries) {
		t.Errorf("CountAll %d exceeds window size %d (leak)", got, maxEntries)
	}

	// IPStats is bounded to the live window (distinct live IPs <= maxEntries).
	if got := int(s.IPStats.Len()); got > maxEntries {
		t.Errorf("IPStats len %d exceeds window size %d (leak)", got, maxEntries)
	}

	// Resident trie nodes must be bounded by the live window, not by every
	// distinct IP ever fed. A leaking trie would carry ~32 nodes per distinct
	// IP (tens of thousands of nodes here); the live window of <=500 distinct
	// IPs caps it far below that. Use a generous bound (<= maxEntries*33 covers
	// up to 32 unique-path nodes per live IP plus the root) that is still
	// orders of magnitude under the leaking count.
	residentNodes := countResidentTrieNodes(s.Trie.Root)
	leakingLowerBound := int(totalDistinctFed) // far below true leak (~32x this), but a trivially failing floor
	if residentNodes >= leakingLowerBound {
		t.Errorf("resident trie nodes %d not bounded to window (looks like a leak; fed %d distinct IPs)",
			residentNodes, totalDistinctFed)
	}
	if residentNodes > maxEntries*33 {
		t.Errorf("resident trie nodes %d exceed window-size bound %d", residentNodes, maxEntries*33)
	}

	// Sanity: the rebuild path must keep the trie answering correctly for the
	// surviving window. CountAll equals the number of live queue entries.
	if got, want := int(s.Trie.CountAll()), len(s.IPQueue); got != want {
		t.Errorf("CountAll %d != live IPQueue len %d after rebuilds", got, want)
	}
}
