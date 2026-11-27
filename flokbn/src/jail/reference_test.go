package jail

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
	active := func(r Record) bool { return now < m.end(r) }
	bans := map[cidr.NumericCIDR]uint8{}
	ban := func(r Record, stage uint8) { bans[r.CIDR()] = max(bans[r.CIDR()], stage) }
	for _, nc := range detected {
		q := Record{IP: nc.Interval().Start, PrefixLen: nc.PrefixLen}
		// sameOffender: r lies around q, and q fills at least x percent of it.
		sameOffender := func(r Record) bool {
			return r.PrefixLen < q.PrefixLen && holds(r, q) && size(q)*100 >= x*size(r)
		}
		inside := func(r Record) bool { return r.PrefixLen > q.PrefixLen && holds(q, r) }

		// Address by address: is it banned, and which stage has it served in
		// the records inside the range?
		allBanned := true
		served := make([]uint64, len(m.cfg.Stages)+1) // addresses per stage served
		for a := first(q); a <= final(q); a++ {
			banned, stage := false, uint8(0)
			for _, r := range m.recs {
				if a < first(r) || final(r) < a {
					continue
				}
				if active(r) {
					banned = true
				} else if inside(r) {
					stage = max(stage, r.Stage)
				}
			}
			if banned {
				continue // a banned address has served nothing
			}
			allBanned = false
			for l := 1; l <= int(stage); l++ {
				served[l]++
			}
		}
		if allBanned {
			continue // rule 1
		}

		history := uint8(0) // rule 2
		for _, r := range m.recs {
			if !active(r) && (r.CIDR() == q.CIDR() || sameOffender(r)) {
				history = max(history, r.Stage)
			}
		}
		for l := len(served) - 1; l > int(history); l-- {
			if served[l]*100 >= x*size(q) {
				history = uint8(l)
				break
			}
		}
		ban(q, m.next(history))

		for _, r := range m.recs {
			switch {
			case active(r):
			case sameOffender(r): // rule 3
				ban(r, m.next(r.Stage))
			case inside(r): // rule 4
				covered := slices.ContainsFunc(m.recs, func(a Record) bool { return active(a) && holds(a, r) })
				if !covered {
					ban(r, m.next(r.Stage))
				}
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
	// A clock that steps back: the jail stays at the latest time it has seen.
	-time.Hour, -200 * 24 * time.Hour,
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
	c.spare, c.det, c.bans = nil, nil, nil
	return &c
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

	// clock is what the calls are handed, now the time the jail works with:
	// the latest one it has seen.
	clock, now := t0, time.Time{}
	for round := 0; !s.done() && round < 200; round++ {
		clock = clock.Add(scriptSteps[s.next()%len(scriptSteps)])
		if round == 0 || clock.After(now) {
			now = clock
		}
		t64 := now.UnixNano()
		detected := make([]cidr.NumericCIDR, s.next()%5)
		for i := range detected {
			detected[i] = s.cidr()
		}

		before := cloneJail(j)
		out := j.Update(clock, detected)
		ref.update(t64, detected)
		recs := j.Records()

		// The reference model agrees.
		if !slices.Equal(recs, ref.recs) {
			t.Fatalf("round %d, detected %v: records differ from the reference model\n got  %v\n want %v\n before %v",
				round, detected, dump(j, now), dump(&Jail{cfg: cfg, durations: j.durations, records: ref.recs}, now), dump(before, now))
		}

		// Sorted, no range twice, valid entries.
		for i, r := range recs {
			if r.PrefixLen > 32 || r.IP != r.CIDR().Interval().Start || r.Stage < 1 || int(r.Stage) > len(cfg.Stages) {
				t.Fatalf("round %d: invalid record %+v", round, r)
			}
			if i > 0 && !recs[i-1].before(r.IP, r.PrefixLen) {
				t.Fatalf("round %d: records %d and %d out of order: %v", round, i-1, i, dump(j, now))
			}
		}

		// Every detected range is banned completely.
		banned := cidr.ParseIntervalSet(j.BanList(clock))
		for _, q := range detected {
			iv := q.Interval()
			for a := uint64(iv.Start); a <= uint64(iv.End); a++ {
				if !banned.Contains(uint32(a)) {
					t.Fatalf("round %d: %s detected, %d not banned: %v", round, q, a, dump(j, now))
				}
			}
		}

		// A record is only replaced once its ban has ended, and only
		// forgotten after its retention.
		for _, r := range before.records {
			switch end := before.banEnd(&r); {
			case t64 < end && !slices.Contains(recs, r):
				t.Fatalf("round %d: the record of the active ban %v changed: %v", round, r, dump(j, now))
			case t64-end <= int64(cfg.Retention) && !slices.ContainsFunc(recs, func(a Record) bool { return a.CIDR() == r.CIDR() }):
				t.Fatalf("round %d: %v was forgotten before its retention: %v", round, r, dump(j, now))
			}
		}

		// A ban never starts above the stage after the highest one its range
		// or a record around or inside it had: nothing is invented.
		for _, r := range recs {
			if r.BanStart != t64 || slices.Contains(before.records, r) {
				continue
			}
			top := uint8(0)
			for _, b := range before.records {
				if (holds(b, r) || holds(r, b)) && t64 >= before.banEnd(&b) {
					top = max(top, b.Stage)
				}
			}
			if r.Stage > before.nextStage(top) {
				t.Fatalf("round %d: %v banned at stage %d, the ended records around and inside it reach stage %d", round, r.CIDR(), r.Stage, top)
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
		if other.Update(clock, shuffled); !slices.Equal(other.Records(), recs) {
			t.Fatalf("round %d: order of %v changes the result", round, detected)
		}

		// The same round again changes nothing: everything detected is banned.
		again := cloneJail(j)
		if o := again.Update(clock, detected); o.Changed() || o.Ignored != len(detected) {
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
		wide.Update(clock, widened)
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
