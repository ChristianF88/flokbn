package jailv2

// The reference model: the rules of the package comment written out address by
// address over a plain list, with no sorted slice, no binary search and no
// single pass. It is slow and only works on small ranges. checkScript runs
// the jail and the model side by side on scripts of rounds and requires the
// same records after every round, plus the properties a caller relies on.

import (
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/cidr"
)

type refJail struct {
	cfg  Config
	recs []Record
}

func (m *refJail) end(r Record) int64 { return r.BanStart + int64(m.cfg.Stages[r.Stage-1]) }

func (m *refJail) next(stage uint8) uint8 {
	if int(stage) < len(m.cfg.Stages) {
		return stage + 1
	}
	return stage
}

func first(r Record) uint64 { return uint64(r.IP) }
func size(r Record) uint64  { return 1 << (32 - r.PrefixLen) }
func final(r Record) uint64 { return first(r) + size(r) - 1 }

// holds reports whether a covers every address of b.
func holds(a, b Record) bool { return first(a) <= first(b) && final(b) <= final(a) }

func (m *refJail) update(now int64, detected []cidr.NumericCIDR) {
	// Forget.
	m.recs = slices.DeleteFunc(m.recs, func(r Record) bool {
		return now-m.end(r) > int64(m.cfg.Retention)
	})

	// Judge every detected range against the records as they are now.
	x := uint64(m.cfg.Overlap)
	bans := map[cidr.NumericCIDR]uint8{}
	for _, nc := range detected {
		q := Record{IP: nc.Interval().Start, PrefixLen: nc.PrefixLen}

		allBanned := true
		reached := make([]uint64, len(m.cfg.Stages)+1) // addresses per level reached
		for a := first(q); a <= final(q); a++ {
			level, banned := 0, false
			for _, r := range m.recs {
				if first(r) > a || final(r) < a {
					continue
				}
				l := int(r.Stage)
				if now < m.end(r) {
					banned = true
					l--
				}
				level = max(level, l)
			}
			if !banned {
				allBanned = false
			}
			for l := 1; l <= level; l++ {
				reached[l]++
			}
		}
		if allBanned {
			continue // rule 1
		}

		history := uint8(0) // rule 2
		for l := 1; l < len(reached); l++ {
			if reached[l]*100 >= x*size(q) {
				history = uint8(l)
			}
		}
		bans[q.CIDR()] = max(bans[q.CIDR()], m.next(history))

		for _, r := range m.recs { // rule 3
			if holds(r, q) && r.PrefixLen != q.PrefixLen && now >= m.end(r) && size(q)*100 >= x*size(r) {
				bans[r.CIDR()] = max(bans[r.CIDR()], m.next(r.Stage))
			}
		}
	}

	// Apply.
	for nc, stage := range bans {
		banned := Record{IP: nc.IP, PrefixLen: nc.PrefixLen, Stage: stage, BanStart: now}
		i := slices.IndexFunc(m.recs, func(r Record) bool { return r.CIDR() == nc })
		if i < 0 {
			m.recs = append(m.recs, banned)
		} else {
			m.recs[i] = banned
		}
	}

	// Tidy: every record is compared with every other one as they stand
	// after the bans.
	all := slices.Clone(m.recs)
	m.recs = slices.DeleteFunc(m.recs, func(r Record) bool {
		for _, a := range all {
			if a.PrefixLen < r.PrefixLen && holds(a, r) && a.Stage >= r.Stage && m.end(a) >= m.end(r) {
				return true
			}
		}
		return false
	})

	slices.SortFunc(m.recs, func(a, b Record) int {
		if a.IP != b.IP {
			if a.IP < b.IP {
				return -1
			}
			return 1
		}
		return int(a.PrefixLen) - int(b.PrefixLen)
	})
}

// The scripts play in 10.20.0.0/22: 1024 addresses, prefix lengths 22 to 32.
const (
	arenaIP     = uint32(10)<<24 | 20<<16
	arenaPrefix = 22
)

// widen maps a range of the arena onto the whole address space: the arena
// becomes 0.0.0.0/0, an address of it a /10. Sizes keep their ratios, so the
// rules must give the same result there.
func widen(nc cidr.NumericCIDR) cidr.NumericCIDR {
	return cidr.NumericCIDR{IP: (nc.IP - arenaIP) << arenaPrefix, PrefixLen: nc.PrefixLen - arenaPrefix}
}

var scriptSteps = []time.Duration{
	0, time.Second, 9 * time.Minute, 11 * time.Minute, 3 * time.Hour, 5 * time.Hour,
	6 * 24 * time.Hour, 8 * 24 * time.Hour, 31 * 24 * time.Hour, 90 * 24 * time.Hour,
	181 * 24 * time.Hour, 400 * 24 * time.Hour,
}

var scriptConfigs = []Config{
	DefaultConfig(),
	{Stages: DefaultConfig().Stages, Overlap: 25, Retention: 180 * 24 * time.Hour},
	{Stages: DefaultConfig().Stages, Overlap: 100, Retention: 180 * 24 * time.Hour},
	{Stages: DefaultConfig().Stages, Overlap: 1, Retention: 30 * 24 * time.Hour},
	{Stages: DefaultConfig().Stages, Overlap: 51, Retention: 0},
	{Stages: []time.Duration{10 * time.Minute}, Overlap: 50, Retention: time.Hour},
	{Stages: []time.Duration{10 * time.Minute, 10 * time.Minute, 7 * 24 * time.Hour}, Overlap: 13, Retention: 400 * 24 * time.Hour},
}

// script reads the rounds of a test from bytes, so that a fuzzer and a random
// generator can both write them. It yields zeros when the bytes run out.
type script struct {
	data []byte
	pos  int
}

func (s *script) done() bool { return s.pos >= len(s.data) }

func (s *script) next() int {
	if s.done() {
		return 0
	}
	b := s.data[s.pos]
	s.pos++
	return int(b)
}

// cidr reads one range of the arena: a prefix length and a position.
func (s *script) cidr() cidr.NumericCIDR {
	prefix := uint8(arenaPrefix + s.next()%(33-arenaPrefix))
	offset := uint32(s.next())<<8 | uint32(s.next())
	ip := arenaIP | offset&(1<<(32-arenaPrefix)-1)
	return cidr.NumericCIDR{IP: ip &^ (^uint32(0) >> prefix), PrefixLen: prefix}
}

func cloneJail(j *Jail) *Jail {
	c := *j
	c.records = slices.Clone(j.records)
	c.spare, c.bans = nil, nil
	return &c
}

// coveredUntil reports whether a record of j that is active at time now and
// stays so until end or later covers the whole of r.
func coveredUntil(j *Jail, r Record, now, end int64) bool {
	for _, a := range j.records {
		if holds(a, r) && now < j.banEnd(&a) && j.banEnd(&a) >= end {
			return true
		}
	}
	return false
}

// checkScript runs one script and checks the jail after every round.
func checkScript(t *testing.T, data []byte) {
	t.Helper()
	s := &script{data: data}
	cfg := scriptConfigs[s.next()%len(scriptConfigs)]

	j, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	wide, _ := New(cfg) // the same script on the whole address space
	ref := &refJail{cfg: cfg}
	shuffle := rand.New(rand.NewSource(int64(len(data))))

	now := t0
	for round := 0; !s.done() && round < 200; round++ {
		now = now.Add(scriptSteps[s.next()%len(scriptSteps)])
		t64 := now.UnixNano()
		detected := make([]cidr.NumericCIDR, s.next()%5)
		for i := range detected {
			detected[i] = s.cidr()
		}

		before := cloneJail(j)
		out := j.Update(now, detected)
		ref.update(t64, detected)
		recs := j.Records()

		// The reference model agrees.
		if !slices.Equal(recs, ref.recs) {
			t.Fatalf("round %d, detected %v: records differ from the reference model\n got  %v\n want %v\n before %v",
				round, detected, dump(j, now), dump(&Jail{cfg: cfg, durations: j.durations, records: ref.recs}, now), dump(before, now))
		}

		// Sorted, no range twice, valid entries, tidy.
		for i, r := range recs {
			if r.PrefixLen > 32 || r.IP != r.CIDR().Interval().Start || r.Stage < 1 || int(r.Stage) > len(cfg.Stages) {
				t.Fatalf("round %d: invalid record %+v", round, r)
			}
			if i > 0 && !recs[i-1].before(r.IP, r.PrefixLen) {
				t.Fatalf("round %d: records %d and %d out of order: %v", round, i-1, i, dump(j, now))
			}
			for _, a := range recs[:i] {
				if a.PrefixLen < r.PrefixLen && holds(a, r) && a.Stage >= r.Stage && j.banEnd(&a) >= j.banEnd(&r) {
					t.Fatalf("round %d: %v is covered by %v and was not absorbed", round, r, a)
				}
			}
		}

		// Every detected range is banned completely.
		banned := cidr.ParseIntervalSet(j.BanList(now))
		for _, q := range detected {
			iv := q.Interval()
			for a := uint64(iv.Start); a <= uint64(iv.End); a++ {
				if !banned.Contains(uint32(a)) {
					t.Fatalf("round %d: %s detected, %d not banned: %v", round, q, a, dump(j, now))
				}
			}
		}

		// A ban that was active is still in force for at least as long.
		for _, r := range before.records {
			if end := before.banEnd(&r); t64 < end && !coveredUntil(j, r, t64, end) {
				t.Fatalf("round %d: active ban %v was dropped or shortened: %v", round, r, dump(j, now))
			}
		}

		// A ban starts only on a detected range or on a range the jail knew.
		for _, r := range recs {
			if r.BanStart != t64 || slices.Contains(before.records, r) {
				continue
			}
			if !slices.Contains(detected, r.CIDR()) &&
				!slices.ContainsFunc(before.records, func(b Record) bool { return b.CIDR() == r.CIDR() }) {
				t.Fatalf("round %d: ban on %v, which was neither detected nor in the jail", round, r)
			}
		}

		// The outcome says whether the records changed.
		if changed := !slices.Equal(recs, before.records); changed != out.Changed() {
			t.Fatalf("round %d: records changed = %v, outcome %+v", round, changed, out)
		}
		if out.Ignored > len(detected) {
			t.Fatalf("round %d: %d of %d detected ranges ignored", round, out.Ignored, len(detected))
		}

		// The order of the detected ranges does not matter.
		other := cloneJail(before)
		shuffled := slices.Clone(detected)
		shuffle.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		if other.Update(now, shuffled); !slices.Equal(other.Records(), recs) {
			t.Fatalf("round %d: order of %v changes the result", round, detected)
		}

		// The same round again changes nothing: everything detected is banned.
		again := cloneJail(j)
		if o := again.Update(now, detected); o.Changed() || o.Ignored != len(detected) {
			t.Fatalf("round %d: repeating the round: %+v", round, o)
		}

		// The file format keeps every record.
		back, err := Decode(j.Encode(), cfg)
		if err != nil || !slices.Equal(back.Records(), recs) {
			t.Fatalf("round %d: encode and decode: err %v\n got  %v\n want %v", round, err, dump(back, now), dump(j, now))
		}

		// The same round on the whole address space gives the same picture.
		widened := make([]cidr.NumericCIDR, len(detected))
		for i, q := range detected {
			widened[i] = widen(q)
		}
		wide.Update(now, widened)
		if len(wide.Records()) != len(recs) {
			t.Fatalf("round %d: %d records on the whole address space, %d in the arena", round, len(wide.Records()), len(recs))
		}
		for i, r := range recs {
			w := wide.Records()[i]
			if w.CIDR() != widen(r.CIDR()) || w.Stage != r.Stage || w.BanStart != r.BanStart {
				t.Fatalf("round %d: record %d on the whole address space is %v, in the arena %v", round, i, w, r)
			}
		}
	}
}

// TestAgainstReference runs random scripts. Ranges are drawn from few
// positions so that they meet again as the same, nested and sibling ranges.
func TestAgainstReference(t *testing.T) {
	scripts := 400
	if testing.Short() {
		scripts = 60
	}
	rng := rand.New(rand.NewSource(1))
	for n := 0; n < scripts; n++ {
		data := make([]byte, 1+rng.Intn(240))
		for i := range data {
			data[i] = byte(rng.Intn(256))
		}
		// Every second script uses only a quarter of the positions, where
		// ranges meet much more often.
		if n%2 == 0 {
			for i := range data {
				data[i] &= 0x3f
			}
		}
		checkScript(t, data)
		if t.Failed() {
			t.Fatalf("script %d: %v", n, data)
		}
	}
}

func FuzzUpdate(f *testing.F) {
	f.Add([]byte{0, 1, 2, 2, 0, 0, 3, 0, 0, 3, 1, 2, 0, 0})
	f.Add([]byte{1, 0, 1, 10, 0, 5, 3, 1, 4, 0, 0, 3, 1, 6, 0, 64})
	f.Add([]byte{6, 2, 4, 0, 0, 0, 1, 0, 0, 2, 0, 0, 10, 0, 0, 5, 1, 1, 2, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 400 {
			return
		}
		checkScript(t, data)
	})
}
