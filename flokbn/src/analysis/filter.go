package analysis

import (
	"runtime"
	"sync"
	"sync/atomic"
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

// concurrentFilterMin is the request count above which a trie's filters run on
// several goroutines. Below it the fan-out costs more than it saves.
const concurrentFilterMin = 50000

// filterResult is what one trie's filters selected from the parsed requests.
type filterResult struct {
	// ips holds one entry per request that passed every filter, in no
	// particular order: the IPs to insert into the trie.
	ips []uint32
	// invalid counts requests that passed the trie's time and regex filters but
	// carry no usable IP (0.0.0.0, or a host field that failed to parse).
	invalid int
	// uaExcluded counts requests dropped only because their User-Agent is on the
	// global whitelist.
	uaExcluded int
	// uaWhitelistIPs / uaBlacklistIPs list the IP of every request seen with a
	// whitelisted / blacklisted User-Agent: one entry per request, so an IP
	// repeats. The pipeline sorts and de-duplicates them once for all tries.
	uaWhitelistIPs []uint32
	uaBlacklistIPs []uint32
}

// add runs the trie's filters over requests and accumulates the outcome. This
// is THE filter: the sequential and the concurrent path both go through it, so
// they cannot drift apart.
//
// Order matters for the counters: a request rejected by the time window or a
// regex is not counted anywhere; a zero IP is counted as invalid before any
// User-Agent verdict, so 0.0.0.0 never reaches the UA lists (which become /32
// whitelist and jail entries).
func (f *filterResult) add(requests []ingestor.Request, trieConfig *config.TrieConfig,
	bounds *timeBounds, userAgentMatcher *cidr.UserAgentMatcher) {

	for i := range requests {
		r := &requests[i]

		if bounds.excluded(r.Timestamp) {
			continue
		}
		if !trieConfig.ShouldIncludeRequest(*r) {
			continue
		}
		if r.IPUint32 == 0 {
			f.invalid++
			continue
		}

		// Exact-match lookup; a nil matcher lists nothing.
		switch userAgentMatcher.CheckUserAgent(r.UserAgent) {
		case cidr.UserAgentWhitelist:
			f.uaWhitelistIPs = append(f.uaWhitelistIPs, r.IPUint32)
			f.uaExcluded++
			continue
		case cidr.UserAgentBlacklist:
			f.uaBlacklistIPs = append(f.uaBlacklistIPs, r.IPUint32)
		}
		f.ips = append(f.ips, r.IPUint32)
	}
}

// filterRequests applies one trie's filters to the parsed requests, fanning
// out over several goroutines when there are enough requests to pay for it.
func filterRequests(requests []ingestor.Request, trieConfig *config.TrieConfig,
	bounds timeBounds, userAgentMatcher *cidr.UserAgentMatcher) filterResult {

	if len(requests) > concurrentFilterMin {
		return filterConcurrent(requests, trieConfig, bounds, userAgentMatcher)
	}
	return filterSequential(requests, trieConfig, bounds, userAgentMatcher)
}

// filterSequential filters on the calling goroutine.
func filterSequential(requests []ingestor.Request, trieConfig *config.TrieConfig,
	bounds timeBounds, userAgentMatcher *cidr.UserAgentMatcher) filterResult {

	var result filterResult
	result.add(requests, trieConfig, &bounds, userAgentMatcher)
	return result
}

// filterConcurrent splits requests into chunks that a few workers claim and
// filter. Every worker accumulates into a result of its own and the results
// are merged once at the end, so the per-request path takes no lock and sends
// nothing over a channel.
func filterConcurrent(requests []ingestor.Request, trieConfig *config.TrieConfig,
	bounds timeBounds, userAgentMatcher *cidr.UserAgentMatcher) filterResult {

	// Several tries filter at the same time, so more workers per trie only add
	// scheduling overhead.
	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8
	}

	// Two chunks per worker even out uneven regex cost across the log; the
	// bounds keep a chunk large enough to amortize claiming it and small enough
	// to balance.
	chunkSize := len(requests) / (numWorkers * 2)
	if chunkSize < 5000 {
		chunkSize = 5000
	}
	if chunkSize > 50000 {
		chunkSize = 50000
	}

	parts := make([]filterResult, numWorkers)
	var next atomic.Int64 // start index of the next unclaimed chunk
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			// Accumulate on this goroutine's stack and publish once: writing
			// through parts[w] per request would make neighbouring workers
			// share cache lines.
			var part filterResult
			for {
				start := int(next.Add(int64(chunkSize))) - chunkSize
				if start >= len(requests) {
					break
				}
				end := start + chunkSize
				if end > len(requests) {
					end = len(requests)
				}
				part.add(requests[start:end], trieConfig, &bounds, userAgentMatcher)
			}
			parts[w] = part
		}(w)
	}
	wg.Wait()

	return mergeFilterResults(parts)
}

// mergeFilterResults concatenates the workers' results.
func mergeFilterResults(parts []filterResult) filterResult {
	var merged filterResult
	var ips, whitelisted, blacklisted int
	for i := range parts {
		ips += len(parts[i].ips)
		whitelisted += len(parts[i].uaWhitelistIPs)
		blacklisted += len(parts[i].uaBlacklistIPs)
		merged.invalid += parts[i].invalid
		merged.uaExcluded += parts[i].uaExcluded
	}
	// Leave empty lists nil, as the sequential path does.
	if ips > 0 {
		merged.ips = make([]uint32, 0, ips)
	}
	if whitelisted > 0 {
		merged.uaWhitelistIPs = make([]uint32, 0, whitelisted)
	}
	if blacklisted > 0 {
		merged.uaBlacklistIPs = make([]uint32, 0, blacklisted)
	}
	for i := range parts {
		merged.ips = append(merged.ips, parts[i].ips...)
		merged.uaWhitelistIPs = append(merged.uaWhitelistIPs, parts[i].uaWhitelistIPs...)
		merged.uaBlacklistIPs = append(merged.uaBlacklistIPs, parts[i].uaBlacklistIPs...)
	}
	return merged
}
