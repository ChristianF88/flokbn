// Package jailv2 is the redesigned jail: the persistent record of which IPv4
// ranges were banned, at which stage and since when. It is self-contained and
// not yet wired into static or live mode; package jail is still the one in use.
//
// # Model
//
// The jail is a list of records. A record is one CIDR range, the stage of its
// last ban and the time that ban started. The ban of a record at stage s lasts
// Config.Stages[s-1]; it is active until then and ended afterwards. Nothing
// else is stored: whether a ban is active is computed from the time handed to
// each call, so there is no flag on disk that can go stale.
//
// Two CIDR ranges are identical, nested or disjoint, never partly overlapping.
// The overlap of two nested ranges is the share of the wider range that the
// narrower one fills: 50% for a /25 in its /24, 25% for a /26, and so on.
// Config.Overlap is the threshold x, in percent.
//
// # Rules
//
// Update judges every detected range against the jail as it was before the
// call, so the outcome does not depend on the order of the detected ranges:
//
//  1. A range whose addresses are all banned already is ignored. Requests that
//     a firewall blocks may still show up in the log; they must not escalate
//     anything.
//  2. Otherwise the range is banned one stage above its history. Its history
//     is the highest level that at least x percent of its addresses have
//     reached in the records around and inside it. An ended ban counts as its
//     stage, an active one as the stage below (it is not served yet). No
//     history means stage 1.
//  3. Every ended record around the range of which the range fills at least
//     x percent is banned again as a whole, at its next stage.
//
// A new or repeated ban always starts at the time of the call.
//
// # Tidying
//
// After the bans are applied, a record that lies inside another record with an
// equal or higher stage and an equal or later ban end is removed: the wider
// record bans it at least as long and remembers at least the same stage. A
// narrower record with a higher stage stays, nested in the wider one. Sibling
// records are never joined in the jail, only in the ban list (BanList).
//
// A record is forgotten Config.Retention after its ban ended.
//
// # Cost
//
// The records are kept in one slice sorted by address, a range before
// everything inside it. A detected range is judged with binary searches for
// the at most 33 ranges around it and one scan of the records inside it; the
// bans of a round are applied, tidied and pruned in one pass. An update costs
// O(records + detected * log(records)) and does not allocate once the buffers
// have grown. A record takes 16 bytes.
//
// A Jail is not safe for concurrent use.
package jailv2

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ChristianF88/flokbn/cidr"
)

// MaxStages is the largest number of stages a Config may have.
const MaxStages = 16

// maxDuration is the longest ban duration and retention a Config may have.
const maxDuration = 50 * 365 * 24 * time.Hour

// Config holds the settings of a jail.
type Config struct {
	// Stages is the ban duration of each stage, first stage first. Durations
	// must be positive and must not get shorter from one stage to the next.
	Stages []time.Duration
	// Overlap is the threshold x of the rules in percent, 1 to 100: from this
	// share on, a narrower and a wider range count as the same offender.
	Overlap int
	// Retention is how long a record is kept after its ban ended. For that
	// long a new detection still counts as a repeat.
	Retention time.Duration
}

// DefaultConfig returns the stages of the current jail (10 minutes, 4 hours,
// 7, 30 and 180 days), an overlap threshold of 50% and a retention of 180 days.
func DefaultConfig() Config {
	return Config{
		Stages: []time.Duration{
			10 * time.Minute,
			4 * time.Hour,
			7 * 24 * time.Hour,
			30 * 24 * time.Hour,
			180 * 24 * time.Hour,
		},
		Overlap:   50,
		Retention: 180 * 24 * time.Hour,
	}
}

func (c Config) validate() error {
	if len(c.Stages) == 0 || len(c.Stages) > MaxStages {
		return fmt.Errorf("jail needs 1 to %d stages, got %d", MaxStages, len(c.Stages))
	}
	for i, d := range c.Stages {
		if d <= 0 || d > maxDuration {
			return fmt.Errorf("jail stage %d has the duration %s, it must be positive and at most %s", i+1, d, maxDuration)
		}
		if i > 0 && d < c.Stages[i-1] {
			return fmt.Errorf("jail stage %d (%s) is shorter than stage %d (%s)", i+1, d, i, c.Stages[i-1])
		}
	}
	if c.Overlap < 1 || c.Overlap > 100 {
		return fmt.Errorf("jail overlap must be 1 to 100 percent, got %d", c.Overlap)
	}
	if c.Retention < 0 || c.Retention > maxDuration {
		return fmt.Errorf("jail retention must be 0 to %s, got %s", maxDuration, c.Retention)
	}
	return nil
}

// Record is one range in the jail.
type Record struct {
	IP        uint32 // network address
	PrefixLen uint8
	Stage     uint8 // stage of the last ban, 1-based
	BanStart  int64 // start of the last ban, Unix nanoseconds
}

// CIDR returns the range of the record.
func (r Record) CIDR() cidr.NumericCIDR {
	return cidr.NumericCIDR{IP: r.IP, PrefixLen: r.PrefixLen}
}

// last returns the last address of the record's range.
func (r *Record) last() uint32 {
	return r.IP | ^uint32(0)>>r.PrefixLen
}

// before reports whether r sorts before the range ip/prefixLen: by address,
// the wider range first, so a range comes before everything inside it.
func (r *Record) before(ip uint32, prefixLen uint8) bool {
	return r.IP < ip || (r.IP == ip && r.PrefixLen < prefixLen)
}

// Jail is the list of records with its settings. Create one with New or Load.
type Jail struct {
	cfg       Config
	durations [MaxStages + 1]int64 // ban duration by stage, nanoseconds
	retention int64

	// records is sorted by address, a range before everything inside it, and
	// holds no range twice.
	records []Record
	// spare is the buffer the next round is written to; bans collects the
	// bans of the round in progress.
	spare []Record
	bans  []ban
}

// ban is the decision to ban one range at one stage.
type ban struct {
	ip        uint32
	prefixLen uint8
	stage     uint8
}

// New returns an empty jail.
func New(cfg Config) (*Jail, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	j := &Jail{cfg: cfg, retention: int64(cfg.Retention)}
	j.cfg.Stages = slices.Clone(cfg.Stages)
	for i, d := range cfg.Stages {
		j.durations[i+1] = int64(d)
	}
	return j, nil
}

// Config returns the settings of the jail.
func (j *Jail) Config() Config {
	cfg := j.cfg
	cfg.Stages = slices.Clone(cfg.Stages)
	return cfg
}

// Len returns the number of records.
func (j *Jail) Len() int { return len(j.records) }

// Records returns the records in address order, a range before everything
// inside it. The slice is the jail's own: read it, do not keep or change it.
func (j *Jail) Records() []Record { return j.records }

// banEnd returns the time the ban of r ends, in Unix nanoseconds.
func (j *Jail) banEnd(r *Record) int64 {
	return r.BanStart + j.durations[r.Stage]
}

// nextStage returns the stage after stage; the last stage repeats.
func (j *Jail) nextStage(stage uint8) uint8 {
	if int(stage) < len(j.cfg.Stages) {
		return stage + 1
	}
	return uint8(len(j.cfg.Stages))
}

// Outcome reports what one Update did.
type Outcome struct {
	// Ignored is the number of detected ranges that were banned already.
	Ignored int
	// Started is the number of ranges that got a record in this round.
	Started int
	// Repeated is the number of records that were banned again.
	Repeated int
	// Absorbed is the number of records removed because a wider record now
	// covers them.
	Absorbed int
	// Pruned is the number of records forgotten after their retention.
	Pruned int
}

// Changed reports whether the round changed the records, that is, whether the
// jail needs saving. Bans that merely ran out change nothing in the records.
func (o Outcome) Changed() bool {
	return o.Started+o.Repeated+o.Absorbed+o.Pruned > 0
}

// Update runs one round at time now: it forgets the records past their
// retention and bans the detected ranges by the rules in the package comment.
// With nothing detected it only forgets, so a round without traffic never
// starts or escalates a ban.
//
// Host bits in a detected range are ignored. Ranges may repeat or lie inside
// one another; each is judged on its own. Update panics on a prefix length
// above 32, which no parser or trie walk of flokbn produces.
func (j *Jail) Update(now time.Time, detected []cidr.NumericCIDR) Outcome {
	t := now.UnixNano()
	out := Outcome{Pruned: j.prune(t)}

	bans := j.bans[:0]
	for _, q := range detected {
		if q.PrefixLen > 32 {
			panic(fmt.Sprintf("jail: detected range with prefix length %d", q.PrefixLen))
		}
		var ignored bool
		if bans, ignored = j.judge(bans, q.Interval().Start, q.PrefixLen, t); ignored {
			out.Ignored++
		}
	}
	if len(bans) > 0 {
		j.apply(bans, t, &out)
	}
	j.bans = bans[:0]
	return out
}

// UpdateCIDRs is Update for ranges given as strings. Entries that are not
// IPv4 CIDRs are skipped and reported in the error; the others are applied.
func (j *Jail) UpdateCIDRs(now time.Time, detected []string) (Outcome, error) {
	ranges := make([]cidr.NumericCIDR, 0, len(detected))
	var errs []error
	for _, s := range detected {
		nc, ok := cidr.Parse(s)
		if !ok {
			errs = append(errs, fmt.Errorf("%q is not an IPv4 CIDR", s))
			continue
		}
		ranges = append(ranges, nc)
	}
	return j.Update(now, ranges), errors.Join(errs...)
}

// prune removes the records whose ban ended more than the retention ago and
// returns their number.
func (j *Jail) prune(now int64) int {
	expired := func(r *Record) bool { return j.banEnd(r)+j.retention < now }

	// Most rounds forget nothing: find the first record to drop before
	// moving any.
	first := 0
	for first < len(j.records) && !expired(&j.records[first]) {
		first++
	}
	if first == len(j.records) {
		return 0
	}
	kept := j.records[:first]
	for i := first + 1; i < len(j.records); i++ {
		if r := j.records[i]; !expired(&r) {
			kept = append(kept, r)
		}
	}
	pruned := len(j.records) - len(kept)
	j.records = kept
	return pruned
}

// lowerBound returns the index of the first record that does not sort before
// ip/prefixLen: the record of that range if there is one, otherwise the place
// it would take.
func (j *Jail) lowerBound(ip uint32, prefixLen uint8) int {
	lo, hi := 0, len(j.records)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if j.records[mid].before(ip, prefixLen) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

// judge applies the rules to the detected range ip/prefixLen and appends the
// resulting bans. It only reads the records. ignored is true when the range
// is banned already (rule 1); nothing is appended then.
func (j *Jail) judge(bans []ban, ip uint32, prefixLen uint8, now int64) (_ []ban, ignored bool) {
	mark := len(bans)
	size := uint64(1) << (32 - prefixLen)
	x := uint64(j.cfg.Overlap)
	stages := len(j.cfg.Stages)

	// The records around the range: at most one per prefix length, each
	// covering the range completely.
	history := uint8(0)
	for p := uint8(0); p < prefixLen; p++ {
		// A shift by 32 yields 0: the /0 mask.
		net := ip & (^uint32(0) << (32 - p))
		i := j.lowerBound(net, p)
		if i == len(j.records) || j.records[i].IP != net || j.records[i].PrefixLen != p {
			continue
		}
		r := &j.records[i]
		if now < j.banEnd(r) {
			return bans[:mark], true // rule 1: banned by an active record
		}
		history = max(history, r.Stage)
		// Rule 3: the range fills at least x percent of this ended record.
		if size*100 >= x<<(32-p) {
			bans = append(bans, ban{ip: r.IP, prefixLen: r.PrefixLen, stage: j.nextStage(r.Stage)})
		}
	}

	// The record of the range itself and the records inside it, which follow
	// it directly. They can be nested, so each address is counted once per
	// level: a record adds its size to a level unless it starts inside the
	// last record counted for that level.
	var covered, until [MaxStages + 1]uint64
	var banned, bannedUntil uint64
	last := uint64(ip) + size - 1
	for i := j.lowerBound(ip, prefixLen); i < len(j.records) && uint64(j.records[i].IP) <= last; i++ {
		r := &j.records[i]
		start, rsize := uint64(r.IP), uint64(1)<<(32-r.PrefixLen)
		level := int(r.Stage)
		if now < j.banEnd(r) {
			level-- // an active ban is not served yet
			if start >= bannedUntil {
				banned += rsize
				bannedUntil = start + rsize
			}
		}
		for l := 1; l <= level; l++ {
			if start >= until[l] {
				covered[l] += rsize
				until[l] = start + rsize
			}
		}
	}
	if banned == size {
		return bans[:mark], true // rule 1: banned by the range's own record or those inside
	}

	// Rule 2: the highest level that at least x percent of the range reached.
	for l := stages; l > int(history); l-- {
		if covered[l]*100 >= x*size {
			history = uint8(l)
			break
		}
	}
	return append(bans, ban{ip: ip, prefixLen: prefixLen, stage: j.nextStage(history)}), false
}

// apply merges the bans of a round into the records and tidies the result,
// in one pass over both.
func (j *Jail) apply(bans []ban, now int64, out *Outcome) {
	// Same order as the records; the highest stage first where several bans
	// name one range.
	slices.SortFunc(bans, func(a, b ban) int {
		switch {
		case a.ip != b.ip:
			if a.ip < b.ip {
				return -1
			}
			return 1
		case a.prefixLen != b.prefixLen:
			return int(a.prefixLen) - int(b.prefixLen)
		default:
			return int(b.stage) - int(a.stage)
		}
	})

	recs := j.records
	t := tidier{jail: j, kept: slices.Grow(j.spare[:0], len(recs)+len(bans))}
	i, k := 0, 0
	for i < len(recs) || k < len(bans) {
		if k == len(bans) || (i < len(recs) && recs[i].before(bans[k].ip, bans[k].prefixLen)) {
			if !t.add(recs[i]) {
				out.Absorbed++
			}
			i++
			continue
		}
		b := bans[k]
		for k < len(bans) && bans[k].ip == b.ip && bans[k].prefixLen == b.prefixLen {
			k++
		}
		existed := i < len(recs) && recs[i].IP == b.ip && recs[i].PrefixLen == b.prefixLen
		if existed {
			i++
		}
		kept := t.add(Record{IP: b.ip, PrefixLen: b.prefixLen, Stage: b.stage, BanStart: now})
		switch {
		case kept && existed:
			out.Repeated++
		case kept:
			out.Started++
		case existed:
			out.Absorbed++
		}
	}
	j.records, j.spare = t.kept, recs[:0]
}

// tidier builds a tidy record list from records handed to it in sorted order.
type tidier struct {
	jail *Jail
	kept []Record
	// around holds the indexes in kept of the records around the position
	// reached: a chain of nested ranges, at most one per prefix length.
	around [33]int
	depth  int
}

// add appends r unless a kept record around it has an equal or higher stage
// and an equal or later ban end, and reports whether it appended. Records
// must arrive in sorted order and no range twice.
func (t *tidier) add(r Record) bool {
	for t.depth > 0 && t.kept[t.around[t.depth-1]].last() < r.IP {
		t.depth--
	}
	// A record that was dropped is not in the chain. That loses nothing: the
	// record that covered it covers everything the dropped one would have.
	end := t.jail.banEnd(&r)
	for _, i := range t.around[:t.depth] {
		a := &t.kept[i]
		if a.Stage >= r.Stage && t.jail.banEnd(a) >= end {
			return false
		}
	}
	t.kept = append(t.kept, r)
	t.around[t.depth] = len(t.kept) - 1
	t.depth++
	return true
}

// Ban is an active ban.
type Ban struct {
	CIDR  cidr.NumericCIDR
	Stage int
	Start time.Time
	End   time.Time
}

// Active returns the bans that are active at time now, one per record, in
// address order. Nested records are listed each on their own.
func (j *Jail) Active(now time.Time) []Ban {
	t := now.UnixNano()
	bans := []Ban{}
	for i := range j.records {
		r := &j.records[i]
		if end := j.banEnd(r); t < end {
			bans = append(bans, Ban{
				CIDR:  r.CIDR(),
				Stage: int(r.Stage),
				Start: time.Unix(0, r.BanStart).UTC(),
				End:   time.Unix(0, end).UTC(),
			})
		}
	}
	return bans
}

// BanList returns the smallest list of CIDRs that covers exactly the addresses
// banned at time now, in address order: what goes into the ban file before the
// whitelist is subtracted. Nested bans are listed once and sibling ranges are
// joined here, never in the records.
func (j *Jail) BanList(now time.Time) []string {
	t := now.UnixNano()
	var ranges []cidr.NumericCIDR
	for i := range j.records {
		if r := &j.records[i]; t < j.banEnd(r) {
			ranges = append(ranges, r.CIDR())
		}
	}
	ranges = cidr.MergeCIDRs(ranges)
	list := make([]string, len(ranges))
	for i, nc := range ranges {
		list[i] = nc.String()
	}
	return list
}

// StageCount is the number of records at one stage.
type StageCount struct {
	Stage    int
	Duration time.Duration
	Records  int // all records at this stage
	Active   int // those whose ban is active
}

// StageCounts returns the number of records per stage at time now.
func (j *Jail) StageCounts(now time.Time) []StageCount {
	t := now.UnixNano()
	counts := make([]StageCount, len(j.cfg.Stages))
	for i, d := range j.cfg.Stages {
		counts[i] = StageCount{Stage: i + 1, Duration: d}
	}
	for i := range j.records {
		r := &j.records[i]
		c := &counts[r.Stage-1]
		c.Records++
		if t < j.banEnd(r) {
			c.Active++
		}
	}
	return counts
}
