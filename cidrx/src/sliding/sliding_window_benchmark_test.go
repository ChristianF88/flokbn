package sliding

import (
	"testing"
	"time"

	"github.com/ChristianF88/cidrx/iputils"
)

// BenchmarkSlidingWindowUpdate benchmarks the performance of SlidingWindowTrie
// under a high load of IP insertions and updates.
// Run with: go test -bench=BenchmarkSlidingWindowUpdate -benchmem
func BenchmarkSlidingWindowUpdate(b *testing.B) {
	Ips, err := iputils.RandomIPsFromRange("192.168.0.0/16", 100000)
	if err != nil {
		b.Fatalf("Failed to generate random IPs: %v", err)
	}

	batchSize := 1000

	b.ResetTimer() // Start timing after setup
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		swt := NewSlidingWindowTrie(10*time.Second, 1000000)
		timedIPs := make([]TimedIP, 0, batchSize)
		b.StartTimer()

		for u := 0; u < len(Ips); u++ {
			timedIPs = append(timedIPs, TimedIP{
				IP:   Ips[u],
				Time: time.Now(),
			})

			if u%batchSize == 0 {
				swt.Update(timedIPs)
				timedIPs = make([]TimedIP, 0, batchSize)
			}
		}
	}
}
