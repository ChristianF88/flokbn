// Package jail is the jail: the persistent record of which IPv4 ranges were
// banned, at which stage and since when. Static and live mode both update it
// through analysis.UpdateBans. The package also writes the two files that come
// out of it: the jail file, which holds every record, and the ban file, the
// short list of what is banned now that a firewall reads.
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
//  2. Otherwise the range is banned one stage above its history. That is the
//     highest of: the stage of its own ended record; the stage of every ended
//     record around it of which it fills at least x percent; and the highest
//     stage that at least x percent of its addresses have served in the ended
//     records inside it. An address that is banned now has served nothing: a
//     ban counts once it has ended. No history means stage 1.
//  3. Every ended record around the range of which the range fills at least
//     x percent is banned again as a whole, at its next stage.
//  4. Every ended record inside the range is banned again at its next stage,
//     since all its addresses were detected again. A record that an active
//     ban covers is left alone, like the range in rule 1.
//
// A new or repeated ban always starts at the time of the call.
//
// The threshold works in both directions. With x = 50, a range one prefix bit
// narrower or wider than a record is the same offender; an address inside an
// ended /24 is a new one and starts at stage 1, and so does a /22 around that
// /24, while the /24 moves up on its own (rule 4) and stays nested in it.
//
// Because a ban counts only once it has ended, a stage cannot climb to wider
// and wider ranges round by round: a range around an active ban starts its
// own ladder, and the narrower record keeps its ban.
//
// # Records are kept
//
// A record is replaced when its range is banned again and forgotten
// Config.Retention after its ban ended. Nothing else removes it: a record
// inside a wider one stays, because the wider record does not pass its stage
// down to a range that fills less than x percent of it. The jail therefore
// holds every range that was detected, each with its own stage. Nested and
// neighbouring bans are joined in the ban list only (BanList).
//
// # Time
//
// A call works with the time handed to it, but the jail does not go back: a
// time earlier than the latest one it has seen is replaced by that one, so a
// clock that steps back does not bring ended bans back. The latest time is
// that of the last Update; a jail read from a file starts at the latest ban
// start in the file, so the same holds across a restart. Times outside the
// years 1970 to 2150 are moved to the nearest end of that span.
//
// # Cost
//
// The records are kept in one slice sorted by address, a range before
// everything inside it. An update sorts the detected ranges and judges each
// with binary searches for the at most 33 ranges around it and one scan of
// the records inside it; the bans of a round are applied and the old records
// pruned in one pass. That is O(d log d + d log r + s + r) for d detected
// ranges, r records and s the records inside the detected ranges, counted
// once for every detected range that holds them. An update does not allocate
// once the buffers have grown. A record takes 16 bytes.
//
// A Jail is not safe for concurrent use.
package jail

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/iputils"
)

// MaxStages is the largest number of stages a Config may have.
const MaxStages = 16

// maxDuration is the longest ban duration and retention a Config may have.
const maxDuration = 50 * 365 * 24 * time.Hour

// The times the jail computes with. With durations of at most maxDuration, a
// ban end plus the retention stays inside what an int64 of nanoseconds holds
// (up to the year 2262).
var (
	minTime = time.Unix(0, 0).UTC()
	maxTime = time.Date(2150, 1, 1, 0, 0, 0, 0, time.UTC)
)

// clampNano returns t in Unix nanoseconds, moved into minTime..maxTime.
func clampNano(t time.Time) int64 {
	switch {
	case t.Before(minTime):
		t = minTime
	case t.After(maxTime):
		t = maxTime
	}
	return t.UnixNano()
}

// Config holds the settings of a jail.
type Config struct {
	// Stages is the ban duration of each stage, first stage first. Durations
	// must be positive and must not get shorter from one stage to the next.
	Stages []time.Duration
	// Overlap is the threshold x of the rules in percent of addresses, 1 to
	// 100: from this share on, a narrower and a wider range count as the same
	// offender.
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
	// spare is the buffer the next round is written to; det holds the
	// detected ranges of the round in progress in sorted order, bans the bans
	// decided for it. active, text and ends are the scratch space of BanList.
	spare  []Record
	det    []cidr.NumericCIDR
	bans   []ban
	active []cidr.NumericCIDR
	text   []byte
	ends   []int
	// clock is the latest time the jail has seen, in Unix nanoseconds: that
	// of its last Update, or for a jail read from a file the latest ban start
	// in that file.
	clock int64
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

// at returns the time a call at now works with, in Unix nanoseconds: now, or
// the latest time an Update has seen if that is later.
func (j *Jail) at(now time.Time) int64 {
	return max(clampNano(now), j.clock)
}

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
	// Pruned is the number of records forgotten after their retention.
	Pruned int
	// Ended is the number of bans that ran out since the previous Update. For
	// the first Update of a jail read from a file that is since the latest
	// ban start in the file, which covers the time flokbn was not running. A
	// ban that ran out does not change its record, only the ban list.
	Ended int
}

// Changed reports whether the round changed the records, that is, whether the
// jail needs saving. Bans that merely ran out change nothing in the records.
func (o Outcome) Changed() bool {
	return o.Started+o.Repeated+o.Pruned > 0
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
	t := j.at(now)
	out := Outcome{Ended: j.ended(j.clock, t)}
	j.clock = t
	out.Pruned = j.prune(t)
	if len(detected) == 0 {
		return out
	}

	// In the order of the records: a range before everything inside it, the
	// same range side by side.
	det := j.det[:0]
	for _, q := range detected {
		if q.PrefixLen > 32 {
			panic(fmt.Sprintf("jail: detected range with prefix length %d", q.PrefixLen))
		}
		det = append(det, cidr.NumericCIDR{IP: q.Interval().Start, PrefixLen: q.PrefixLen})
	}
	slices.SortFunc(det, func(a, b cidr.NumericCIDR) int {
		if a.IP != b.IP {
			if a.IP < b.IP {
				return -1
			}
			return 1
		}
		return int(a.PrefixLen) - int(b.PrefixLen)
	})

	bans := j.bans[:0]
	// Rule 4 is done for every address below rebanned: a detected range
	// inside one judged before it would name the same records again.
	var rebanned uint64
	for i := 0; i < len(det); {
		q := det[i]
		n := 1
		for i+n < len(det) && det[i+n] == q {
			n++
		}
		i += n

		start := uint64(q.IP)
		var ignored bool
		bans, ignored = j.judge(bans, q.IP, q.PrefixLen, t, start >= rebanned)
		switch {
		case ignored:
			out.Ignored += n
		case start >= rebanned:
			rebanned = start + uint64(1)<<(32-q.PrefixLen)
		}
	}
	if len(bans) > 0 {
		j.apply(bans, t, &out)
	}
	j.det, j.bans = det[:0], bans[:0]
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

// ended counts the bans that ran out after the time from, up to the time to.
func (j *Jail) ended(from, to int64) int {
	n := 0
	for i := range j.records {
		if end := j.banEnd(&j.records[i]); from < end && end <= to {
			n++
		}
	}
	return n
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
// is banned already (rule 1); nothing is appended then. inner is false when a
// range around this one was judged in the same round and has named the
// records inside it for rule 4 already.
func (j *Jail) judge(bans []ban, ip uint32, prefixLen uint8, now int64, inner bool) (_ []ban, ignored bool) {
	mark := len(bans)
	size := uint64(1) << (32 - prefixLen)
	x := uint64(j.cfg.Overlap)
	stages := len(j.cfg.Stages)

	// The records around the range: at most one per prefix length, each
	// covering the range completely.
	history := uint8(0) // the highest stage of those that count for the range
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
		// The range fills at least x percent of this ended record: the
		// record counts as history (rule 2) and is banned again (rule 3).
		if size*100 >= x<<(32-p) {
			history = max(history, r.Stage)
			bans = append(bans, ban{ip: r.IP, prefixLen: r.PrefixLen, stage: j.nextStage(r.Stage)})
		}
	}

	// The record of the range itself and the records inside it, which follow
	// it directly, a record before everything inside it. covered[l] is the
	// number of addresses that are not banned and lie in an ended record of
	// stage l or higher. Records can be nested, so a record adds its size to
	// a level unless it lies inside the last record counted for that level.
	var covered, until [MaxStages + 1]uint64
	var banned, bannedUntil uint64
	last := uint64(ip) + size - 1
	for i := j.lowerBound(ip, prefixLen); i < len(j.records) && uint64(j.records[i].IP) <= last; i++ {
		r := &j.records[i]
		start, rsize := uint64(r.IP), uint64(1)<<(32-r.PrefixLen)
		if start < bannedUntil {
			continue // inside an active ban: counted as banned already
		}
		if now < j.banEnd(r) {
			banned += rsize
			bannedUntil = start + rsize
			// Banned addresses have served nothing: take them out of the
			// levels the ended records around this one added them to.
			for l := 1; l <= stages; l++ {
				if start < until[l] {
					covered[l] -= rsize
				}
			}
			continue
		}
		for l := 1; l <= int(r.Stage); l++ {
			if start >= until[l] {
				covered[l] += rsize
				until[l] = start + rsize
			}
		}
		if r.PrefixLen == prefixLen {
			history = max(history, r.Stage) // the range's own record
		} else if inner {
			bans = append(bans, ban{ip: r.IP, prefixLen: r.PrefixLen, stage: j.nextStage(r.Stage)}) // rule 4
		}
	}
	if banned == size {
		return bans[:mark], true // rule 1: banned by the range's own record or those inside
	}

	// Rule 2: beyond the records that count as a whole, the highest stage
	// that at least x percent of the range's addresses have served.
	for l := stages; l > int(history); l-- {
		if covered[l]*100 >= x*size {
			history = uint8(l)
			break
		}
	}
	return append(bans, ban{ip: ip, prefixLen: prefixLen, stage: j.nextStage(history)}), false
}

// apply merges the bans of a round into the records, in one pass over both.
// A ban replaces the record of its range or adds one.
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
	next := slices.Grow(j.spare[:0], len(recs)+len(bans))
	i, k := 0, 0
	for i < len(recs) || k < len(bans) {
		if k == len(bans) || (i < len(recs) && recs[i].before(bans[k].ip, bans[k].prefixLen)) {
			next = append(next, recs[i])
			i++
			continue
		}
		b := bans[k]
		for k < len(bans) && bans[k].ip == b.ip && bans[k].prefixLen == b.prefixLen {
			k++
		}
		if i < len(recs) && recs[i].IP == b.ip && recs[i].PrefixLen == b.prefixLen {
			i++
			out.Repeated++
		} else {
			out.Started++
		}
		next = append(next, Record{IP: b.ip, PrefixLen: b.prefixLen, Stage: b.stage, BanStart: now})
	}
	j.records, j.spare = next, recs[:0]
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
	t := j.at(now)
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
// whitelist is subtracted. Only bans that are running are listed. A ban inside
// another one is listed once, as the wider range, and neighbouring ranges are
// joined; that happens here, never in the records.
//
// The entries share one string, so the list costs two allocations however
// long it is.
func (j *Jail) BanList(now time.Time) []string {
	t := j.at(now)
	active := j.active[:0]
	for i := range j.records {
		if r := &j.records[i]; t < j.banEnd(r) {
			active = append(active, r.CIDR())
		}
	}
	merged := cidr.MergeCIDRs(active)
	j.active = active[:0]
	if len(merged) == 0 {
		return []string{}
	}

	text, ends := j.text[:0], j.ends[:0]
	for _, nc := range merged {
		text = appendCIDR(text, nc)
		ends = append(ends, len(text))
	}
	all := string(text)
	list := make([]string, len(ends))
	start := 0
	for i, end := range ends {
		list[i] = all[start:end]
		start = end
	}
	j.text, j.ends = text[:0], ends[:0]
	return list
}

// appendCIDR appends the text of nc, as NumericCIDR.String writes it.
func appendCIDR(buf []byte, nc cidr.NumericCIDR) []byte {
	var text [iputils.MaxIPv4Len + 4]byte
	n := iputils.PutIPv4(text[:], nc.IP)
	text[n] = '/'
	n = iputils.PutUint8(text[:], n+1, nc.PrefixLen)
	return append(buf, text[:n]...)
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
	t := j.at(now)
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
