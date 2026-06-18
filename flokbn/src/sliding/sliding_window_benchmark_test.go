package sliding

import (
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/iputils"
)

// BenchmarkSlidingWindowUpdate benchmarks the performance of SlidingWindowTrie
// under a high load of IP insertions and updates.
// Run with: go test -bench=BenchmarkSlidingWindowUpdate -benchmem
func BenchmarkSlidingWindowUpdate(b *testing.B) {
	Ips, err := iputils.RandomIPsFromRange("192.168.0.0/16", 100000)
	if err != nil {
		b.Fatalf("Failed to generate random IPs: %v", err)
	}

	// Pre-convert net.IP -> uint32 OUTSIDE the timed region. TimedIP.IP is now a
	// uint32 (AUDIT-05); doing the conversion here keeps the benchmark measuring
	// window ops (insert/evict) rather than the one-time IPToUint32 cost, so the
	// allocs/op reduction from dropping the per-request net.IP is attributable to
	// the window path and not muddied by setup conversions.
	ipsU32 := make([]uint32, len(Ips))
	for i := range Ips {
		ipsU32[i] = iputils.IPToUint32(Ips[i])
	}

	batchSize := 1000

	b.ResetTimer() // Start timing after setup
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		swt := NewSlidingWindowTrie(10*time.Second, 1000000)
		timedIPs := make([]TimedIP, 0, batchSize)
		b.StartTimer()

		for u := 0; u < len(ipsU32); u++ {
			timedIPs = append(timedIPs, TimedIP{
				IP:   ipsU32[u],
				Time: time.Now(),
			})

			if u%batchSize == 0 {
				swt.Update(timedIPs)
				timedIPs = make([]TimedIP, 0, batchSize)
			}
		}
	}
}
