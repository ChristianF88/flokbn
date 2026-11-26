package jailv2

// The jail in use (package jail) next to this one: the cases that prompted
// the redesign, and the cost of a round at growing sizes.

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/jail"
)

// oldJailWith returns a jail of package jail holding one range in the cell of
// the given stage, its ban ended.
func oldJailWith(entry string, stage int) jail.Jail {
	old := jail.NewJail()
	cell := &old.Cells[stage-1]
	cell.Prisoners = append(cell.Prisoners, jail.Prisoner{
		CIDR:     entry,
		BanStart: time.Now().Add(-cell.BanDuration - time.Minute),
	})
	old.AllCIDRs = append(old.AllCIDRs, entry)
	old.RefreshBounds()
	return old
}

// stageOf returns the stage of entry in a jail of package jail, 0 if absent.
func stageOf(old jail.Jail, entry string) int {
	for _, cell := range old.Cells {
		for _, p := range cell.Prisoners {
			if p.CIDR == entry {
				return cell.ID
			}
		}
	}
	return 0
}

// TestWideRangeDoesNotInheritNarrow: one address served a 30-day ban. Later
// its /16 is detected. Package jail bans all 65,536 addresses for 180 days;
// here the /16 starts at stage 1.
func TestWideRangeDoesNotInheritNarrow(t *testing.T) {
	old := oldJailWith("10.0.5.5/32", 4)
	if err := old.Update([]string{"10.0.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	if got := stageOf(old, "10.0.0.0/16"); got != 5 {
		t.Errorf("package jail: /16 at stage %d, expected its known behaviour (stage 5)", got)
	}

	j := newJail(t, 50)
	seed(t, j, t0, "10.0.5.5/32 4 ended")
	j.Update(t0, ranges(t, "10.0.0.0/16"))
	wantRecords(t, j, t0, "10.0.0.0/16 1 active", "10.0.5.5/32 4 ended")
}

// TestNarrowRangeDoesNotRelistWide: a /16 served a 7-day ban. Later one
// address in it is detected. Package jail bans the whole /16 again, for 30
// days; here only the address is banned.
func TestNarrowRangeDoesNotRelistWide(t *testing.T) {
	old := oldJailWith("10.0.0.0/16", 3)
	if err := old.Update([]string{"10.0.5.5/32"}); err != nil {
		t.Fatal(err)
	}
	if got := old.ListActiveBans(); !slices.Equal(got, []string{"10.0.0.0/16"}) || stageOf(old, "10.0.0.0/16") != 4 {
		t.Errorf("package jail: active bans %q, expected its known behaviour (the /16 at stage 4)", got)
	}

	j := newJail(t, 50)
	seed(t, j, t0, "10.0.0.0/16 3 ended")
	j.Update(t0, ranges(t, "10.0.5.5/32"))
	if got := j.BanList(t0); !slices.Equal(got, []string{"10.0.5.5/32"}) {
		t.Errorf("ban list %q, want only the address", got)
	}
	wantRecords(t, j, t0, "10.0.0.0/16 3 ended", "10.0.5.5/32 4 active")
}

// TestWideBanDoesNotInheritTimer: a /25 is 9 minutes into its 10-minute ban
// when its /24 is detected. In package jail the /24 takes over the start of
// the /25 and is free again a minute later; here its ban starts now.
func TestWideBanDoesNotInheritTimer(t *testing.T) {
	old := jail.NewJail()
	started := time.Now().Add(-9 * time.Minute)
	old.Cells[0].Prisoners = append(old.Cells[0].Prisoners, jail.Prisoner{CIDR: "10.0.0.0/25", BanStart: started, BanActive: true})
	old.AllCIDRs = append(old.AllCIDRs, "10.0.0.0/25")
	old.RefreshBounds()
	if err := old.Update([]string{"10.0.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	if got := old.Cells[0].Prisoners[0]; got.CIDR != "10.0.0.0/24" || !got.BanStart.Equal(started) {
		t.Errorf("package jail: %+v, expected its known behaviour (the /24 with the start of the /25)", got)
	}

	j := newJail(t, 50)
	j.Update(t0, ranges(t, "10.0.0.0/25"))
	now := t0.Add(9 * time.Minute)
	j.Update(now, ranges(t, "10.0.0.0/24"))
	wantRecords(t, j, now, "10.0.0.0/24 1 active")
	if got := j.Active(now)[0].End; !got.Equal(now.Add(10 * time.Minute)) {
		t.Errorf("the /24 ban ends %s, want 10 minutes after its detection", got)
	}
}

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
	cfg := DefaultConfig()
	cfg.Retention = maxDuration // nothing is forgotten while the clock is moved
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
// banned again, so the round rewrites the records.
func BenchmarkUpdateRepeat(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(fmt.Sprintf("records=%d", n), func(b *testing.B) {
			j, detected := benchJail(b, n)
			now := t0
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				now = now.Add(181 * 24 * time.Hour) // past the longest ban
				if out := j.Update(now, detected); out.Repeated != benchDetected {
					b.Fatalf("outcome %+v", out)
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

// oldBenchJail returns a jail of package jail with n ranges in the first
// cell, and the 100 of them a round detects.
func oldBenchJail(n int, active bool) (jail.Jail, []string) {
	old := jail.NewJail()
	all := benchRanges(n)
	start := time.Now()
	if !active {
		start = start.Add(-time.Hour)
	}
	old.Cells[0].Prisoners = make([]jail.Prisoner, n)
	old.AllCIDRs = make([]string, n)
	for i, nc := range all {
		old.Cells[0].Prisoners[i] = jail.Prisoner{CIDR: nc.String(), BanStart: start, BanActive: active}
		old.AllCIDRs[i] = nc.String()
	}
	old.RefreshBounds()
	detected := make([]string, benchDetected)
	for i, nc := range pick(all) {
		detected[i] = nc.String()
	}
	return old, detected
}

// BenchmarkOldUpdateBanned is BenchmarkUpdateBanned on package jail.
func BenchmarkOldUpdateBanned(b *testing.B) {
	for _, n := range benchSizes[:3] {
		b.Run(fmt.Sprintf("records=%d", n), func(b *testing.B) {
			old, detected := oldBenchJail(n, true)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := old.Update(detected); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkOldUpdateRepeat is BenchmarkUpdateRepeat on package jail: the
// detected ranges have served their ban. The jail is rebuilt each time,
// because a ban of package jail cannot be ended by moving a clock.
func BenchmarkOldUpdateRepeat(b *testing.B) {
	for _, n := range benchSizes[:3] {
		b.Run(fmt.Sprintf("records=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				old, detected := oldBenchJail(n, false)
				b.StartTimer()
				if err := old.Update(detected); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
