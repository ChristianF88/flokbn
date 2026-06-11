package sliding

import (
	"reflect"
	"testing"

	"github.com/alphadose/haxmap"
)

// newWindowWithCounts builds a SlidingWindow whose IPStats holds the given
// ip(uint32) -> count pairs. TopTalkers only reads IPStats, so the trie and
// queue stay empty.
func newWindowWithCounts(counts map[uint32]int) *SlidingWindow {
	m := haxmap.New[uint32, IPStat]()
	for ip, c := range counts {
		m.Set(ip, IPStat{Count: c})
	}
	return &SlidingWindow{IPStats: m}
}

func ipU32(o1, o2, o3, o4 byte) uint32 {
	return uint32(o1)<<24 | uint32(o2)<<16 | uint32(o3)<<8 | uint32(o4)
}

func TestTopTalkers_OrderAndBound(t *testing.T) {
	w := newWindowWithCounts(map[uint32]int{
		ipU32(10, 0, 0, 1): 5,
		ipU32(10, 0, 0, 2): 3,
		ipU32(10, 0, 0, 3): 1,
		ipU32(10, 0, 0, 4): 8,
		ipU32(10, 0, 0, 5): 2,
	})

	got := w.TopTalkers(2)
	want := []TopTalker{
		{IP: "10.0.0.4", Count: 8},
		{IP: "10.0.0.1", Count: 5},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TopTalkers(2) = %+v, want %+v", got, want)
	}
}

func TestTopTalkers_NLargerThanUnique(t *testing.T) {
	w := newWindowWithCounts(map[uint32]int{
		ipU32(10, 0, 0, 1): 5,
		ipU32(10, 0, 0, 2): 3,
	})

	got := w.TopTalkers(10)
	want := []TopTalker{
		{IP: "10.0.0.1", Count: 5},
		{IP: "10.0.0.2", Count: 3},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TopTalkers(10) = %+v, want %+v", got, want)
	}
}

func TestTopTalkers_ZeroAndNegativeN(t *testing.T) {
	w := newWindowWithCounts(map[uint32]int{ipU32(10, 0, 0, 1): 5})
	if got := w.TopTalkers(0); got != nil {
		t.Errorf("TopTalkers(0) = %+v, want nil", got)
	}
	if got := w.TopTalkers(-1); got != nil {
		t.Errorf("TopTalkers(-1) = %+v, want nil", got)
	}
}

func TestTopTalkers_TiesPreferLowerIPs(t *testing.T) {
	// Four IPs with equal counts: the n retained (and reported) must be the
	// numerically smallest, in ascending order.
	w := newWindowWithCounts(map[uint32]int{
		ipU32(10, 0, 0, 9): 4,
		ipU32(10, 0, 0, 1): 4,
		ipU32(10, 0, 0, 7): 4,
		ipU32(10, 0, 0, 3): 4,
	})

	got := w.TopTalkers(2)
	want := []TopTalker{
		{IP: "10.0.0.1", Count: 4},
		{IP: "10.0.0.3", Count: 4},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TopTalkers(2) with ties = %+v, want %+v", got, want)
	}
}

func TestTopTalkers_EmptyWindow(t *testing.T) {
	w := newWindowWithCounts(nil)
	if got := w.TopTalkers(5); len(got) != 0 {
		t.Errorf("TopTalkers on empty window = %+v, want empty", got)
	}
}

func BenchmarkTopTalkers(b *testing.B) {
	const uniqueIPs = 100_000
	m := haxmap.New[uint32, IPStat](uniqueIPs)
	for i := 0; i < uniqueIPs; i++ {
		// Spread counts so the heap sees a mix of replacements and skips.
		m.Set(uint32(i)+ipU32(10, 0, 0, 0), IPStat{Count: (i*7919)%1000 + 1})
	}
	w := &SlidingWindow{IPStats: m}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := w.TopTalkers(20); len(got) != 20 {
			b.Fatalf("TopTalkers returned %d entries, want 20", len(got))
		}
	}
}
