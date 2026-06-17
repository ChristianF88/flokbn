package analysis

import (
	"time"

	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/ingestor"
)

// timeBounds carries the start/end time-range filter plus, per URGENT-09,
// whether each bound carries an EXPLICIT timezone offset. With an explicit
// offset a bound is compared as a TRUE INSTANT; without one (the zone-less
// default) comparison is wall-clock / zone-agnostic, so a bound "06:00" matches
// a log line whose local clock reads 06:00 regardless of the log's offset.
//
// The wall-clock comparison is allocation-free: it compares each side's
// year/month/day/hour/min/sec via a single monotonic int64 key computed without
// any heap allocation (time.Time accessor methods do not allocate).
type timeBounds struct {
	start          time.Time
	end            time.Time
	startSet       bool
	endSet         bool
	startHasOffset bool
	endHasOffset   bool

	// Precomputed wall-clock keys for the zone-less comparison path.
	startWallKey int64
	endWallKey   int64
}

// makeTimeBounds builds the comparison helper from a trie config.
func makeTimeBounds(tc *config.TrieConfig) timeBounds {
	var tb timeBounds
	if tc.StartTime != nil {
		tb.start = *tc.StartTime
		tb.startSet = true
		tb.startHasOffset = tc.StartTimeHasOffset
		tb.startWallKey = wallClockKey(tb.start)
	}
	if tc.EndTime != nil {
		tb.end = *tc.EndTime
		tb.endSet = true
		tb.endHasOffset = tc.EndTimeHasOffset
		tb.endWallKey = wallClockKey(tb.end)
	}
	return tb
}

// wallClockKey maps a time's local wall-clock fields (ignoring its zone) to a
// monotonically ordered int64, so two wall-clocks can be compared zone-agnostic.
// Allocation-free: all accessors return scalars.
func wallClockKey(t time.Time) int64 {
	y, mo, d := t.Date()
	h, mi, s := t.Clock()
	// Pack into a comparable key. Component ranges are bounded, so naive
	// positional weighting preserves ordering. Year dominates.
	return ((((int64(y)*12+int64(mo-1))*31+int64(d-1))*24+int64(h))*60+int64(mi))*60 + int64(s)
}

// excluded reports whether a request timestamp falls outside the bounds. For
// each set bound it uses a true-instant comparison when the bound carries an
// explicit offset, else a wall-clock (zone-agnostic) comparison.
func (tb *timeBounds) excluded(ts time.Time) bool {
	if tb.startSet {
		if tb.startHasOffset {
			if ts.Before(tb.start) {
				return true
			}
		} else if wallClockKey(ts) < tb.startWallKey {
			return true
		}
	}
	if tb.endSet {
		if tb.endHasOffset {
			if ts.After(tb.end) {
				return true
			}
		} else if wallClockKey(ts) > tb.endWallKey {
			return true
		}
	}
	return false
}

// requestChunk represents a chunk of requests for parallel processing
type requestChunk struct {
	requests []ingestor.Request
}

// filterResult represents the result of filtering a single request
type filterResult struct {
	request         ingestor.Request
	shouldInclude   bool
	isWhitelistedUA bool
	isBlacklistedUA bool
}

// filterWorker processes request chunks concurrently
func filterWorker(
	requestChan <-chan requestChunk,
	resultChan chan<- filterResult,
	trieConfig *config.TrieConfig,
	bounds timeBounds,
	userAgentMatcher *cidr.UserAgentMatcher) {

	for chunk := range requestChan {
		for _, r := range chunk.requests {
			result := filterResult{
				request: r,
			}

			// Apply time filtering — skip rejected requests entirely (no channel send)
			if bounds.excluded(r.Timestamp) {
				continue
			}

			// Apply regex filtering (this is expensive and benefits from concurrency)
			if !trieConfig.ShouldIncludeRequest(r) {
				continue
			}

			// Check User-Agent patterns using ultra-fast exact matching
			if userAgentMatcher != nil {
				uaResult := userAgentMatcher.CheckUserAgent(r.UserAgent)
				result.isWhitelistedUA = (uaResult == cidr.UserAgentWhitelist)
				result.isBlacklistedUA = (uaResult == cidr.UserAgentBlacklist)
			}

			// Include in results if not whitelisted by User-Agent
			if !result.isWhitelistedUA {
				result.shouldInclude = true
			}

			resultChan <- result
		}
	}
}
