package cli

import "time"

const (
	// liveRejectedLinesMsg warns that the parser rejects most of what
	// arrives. Without it a logFormat that does not match the shipped lines
	// shows only as a rising parse-error counter, while flokbn detects
	// nothing.
	liveRejectedLinesMsg = "most log lines are rejected by the parser"
	// liveRejectedLinesInterval rate-limits that warning.
	liveRejectedLinesInterval = time.Minute
	// liveRejectedLinesMin is how many lines must have arrived before their
	// rejected share is judged, so that one stray line in a tiny batch does
	// not count as "most". Lines are carried over between reads until there
	// are that many.
	liveRejectedLinesMin = 20
)

// rejectWatch follows the ingestor's parsed and rejected line totals and
// decides when the rejected share deserves a warning: more than half of at
// least liveRejectedLinesMin lines, at most once per
// liveRejectedLinesInterval. Owned by the loop goroutine.
type rejectWatch struct {
	seenParsed   uint64 // ingestor totals at the last observe
	seenRejected uint64
	parsed       uint64 // lines since the last judgement
	rejected     uint64
	lastWarn     time.Time
}

// observe takes the ingestor's lifetime totals. When a warning is due it
// returns the parsed and rejected line counts it is based on and true.
func (r *rejectWatch) observe(parsedTotal, rejectedTotal uint64, now time.Time) (parsed, rejected uint64, warn bool) {
	r.parsed += parsedTotal - r.seenParsed
	r.rejected += rejectedTotal - r.seenRejected
	r.seenParsed, r.seenRejected = parsedTotal, rejectedTotal

	if r.parsed+r.rejected < liveRejectedLinesMin {
		return 0, 0, false
	}
	parsed, rejected = r.parsed, r.rejected
	r.parsed, r.rejected = 0, 0
	if rejected <= parsed || now.Sub(r.lastWarn) < liveRejectedLinesInterval {
		return 0, 0, false
	}
	r.lastWarn = now
	return parsed, rejected, true
}
