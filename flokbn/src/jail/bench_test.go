package jail

// The cost of a round at growing jail sizes.

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/cidr"
)

// benchRanges returns n disjoint /24 ranges spread over the address space.
func benchRanges(n int) []cidr.NumericCIDR {
	out := make([]cidr.NumericCIDR, n)
	step := uint32(1<<24) / uint32(n)
	if step == 0 {
		step = 1
	}
	for i := range out {
		out[i] = cidr.NumericCIDR{IP: uint32(i) * step << 8, PrefixLen: 24}
	}
	return out
}

// benchSizes are the jail sizes of the benchmarks; a round detects 100 ranges.
var benchSizes = []int{1_000, 10_000, 100_000, 1_000_000}

const benchDetected = 100

// pick returns benchDetected of the ranges, evenly spread.
func pick(all []cidr.NumericCIDR) []cidr.NumericCIDR {
	out := make([]cidr.NumericCIDR, benchDetected)
	for i := range out {
		out[i] = all[i*(len(all)/benchDetected)]
	}
	return out
}

func benchJail(b *testing.B, n int) (*Jail, []cidr.NumericCIDR) {
	return benchJailWith(b, n, DefaultConfig())
}

func benchJailWith(b *testing.B, n int, cfg Config) (*Jail, []cidr.NumericCIDR) {
	j, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}
	all := benchRanges(n)
	j.Update(t0, all)
	return j, pick(all)
}

// BenchmarkUpdateBanned: every detected range is banned already, the usual
// round while an attack goes on. Nothing changes; the cost is the lookups.
func BenchmarkUpdateBanned(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(fmt.Sprintf("records=%d", n), func(b *testing.B) {
			j, detected := benchJail(b, n)
			now := t0.Add(time.Minute)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if out := j.Update(now, detected); out.Ignored != benchDetected {
					b.Fatalf("outcome %+v", out)
				}
			}
		})
	}
}

// BenchmarkUpdateRepeat: every detected range has served its ban and is
// banned again, so the round rewrites the records. The stages last a
// nanosecond each: two nanoseconds on, every ban has ended, and the clock
// stays where it is however long the benchmark runs.
func BenchmarkUpdateRepeat(b *testing.B) {
	cfg := DefaultConfig()
	cfg.Stages = []time.Duration{1, 1, 1, 1, 1}
	for _, n := range benchSizes {
		b.Run(fmt.Sprintf("records=%d", n), func(b *testing.B) {
			j, detected := benchJailWith(b, n, cfg)
			now := t0
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				now = now.Add(2)
				if out := j.Update(now, detected); out.Repeated != benchDetected || j.Len() != n {
					b.Fatalf("outcome %+v, %d records", out, j.Len())
				}
			}
		})
	}
}

// BenchmarkUpdateNew: every detected range is new and lies between the
// records, so the round inserts 100 records. The jail is rebuilt each time.
func BenchmarkUpdateNew(b *testing.B) {
	for _, n := range benchSizes[:3] {
		b.Run(fmt.Sprintf("records=%d", n), func(b *testing.B) {
			j, detected := benchJail(b, n)
			fresh := make([]cidr.NumericCIDR, len(detected))
			for i, q := range detected {
				fresh[i] = cidr.NumericCIDR{IP: q.IP | 0x80, PrefixLen: 32} // an address of a banned /24 ...
			}
			base := slices.Clone(j.records)
			now := t0.Add(181 * 24 * time.Hour) // ... whose ban has ended
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				j.records = append(j.records[:0], base...)
				b.StartTimer()
				if out := j.Update(now, fresh); out.Started != benchDetected {
					b.Fatalf("outcome %+v", out)
				}
			}
		})
	}
}

func BenchmarkBanList(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(fmt.Sprintf("records=%d", n), func(b *testing.B) {
			j, _ := benchJail(b, n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if got := j.BanList(t0); len(got) == 0 {
					b.Fatal("empty ban list")
				}
			}
		})
	}
}

func BenchmarkEncodeDecode(b *testing.B) {
	for _, n := range benchSizes[:3] {
		j, _ := benchJail(b, n)
		data := j.Encode()
		b.Run(fmt.Sprintf("encode/records=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				j.Encode()
			}
		})
		b.Run(fmt.Sprintf("decode/records=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Decode(data, j.cfg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
