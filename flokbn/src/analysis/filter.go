package analysis

import (
	"runtime"
	"sync"
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

			// Apply time filtering - skip rejected requests entirely (no channel send)
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

// filterRequestsConcurrent implements high-performance concurrent filtering
func filterRequestsConcurrent(
	requests []ingestor.Request,
	trieConfig *config.TrieConfig,
	bounds timeBounds,
	userAgentMatcher *cidr.UserAgentMatcher,
	userAgentWhitelistIPSet, userAgentBlacklistIPSet map[uint32]struct{},
	filteredRequestCount *int,
	ipsToInsert *[]uint32,
	invalidIPCount *int,
	uaWhitelistExcluded *int) error {

	// Determine optimal worker count for filtering. The caller (processTrie) only
	// takes this concurrent path when len(requests) > 50000, so only the >8 cap matters.
	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8 // Cap at 8 to reduce contention and mutex overhead
	}

	// Channels for work distribution - smaller buffers reduce memory overhead
	requestChan := make(chan requestChunk, numWorkers)
	resultChan := make(chan filterResult, numWorkers*4)

	// Worker synchronization
	var wg sync.WaitGroup

	// Start filter workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			filterWorker(requestChan, resultChan, trieConfig, bounds,
				userAgentMatcher)
		}()
	}

	// Start result collector. Only this single goroutine touches the UA
	// whitelist/blacklist sets and the local counters, so no mutex is needed
	// around them.
	var collectorWG sync.WaitGroup

	// Track invalid IPs in collector
	var localInvalidCount int
	// Track requests excluded solely by the UA whitelist (passed all other
	// filters but were dropped because their User-Agent is whitelisted).
	var localUAExcluded int
	// Track requests that pass filtering and are inserted into the trie.
	var localFilteredCount int

	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for result := range resultChan {
			// A zero IP (invalid or failed to parse) is counted as invalid FIRST,
			// regardless of the UA verdict - this matches sequential filterRequests,
			// which checks IPUint32==0 before any UA logic. A 0.0.0.0 entry must
			// never reach the UA-excluded counter or the whitelist/blacklist IP sets
			// (those are converted to /32s for jail/ban processing).
			if result.request.IPUint32 == 0 {
				localInvalidCount++
				continue
			}

			if result.shouldInclude {
				*ipsToInsert = append(*ipsToInsert, result.request.IPUint32)
				localFilteredCount++
			} else if result.isWhitelistedUA {
				localUAExcluded++
			}

			// Collect User-Agent whitelist IPs
			if result.isWhitelistedUA {
				userAgentWhitelistIPSet[result.request.IPUint32] = struct{}{}
			}

			// Collect User-Agent blacklist IPs
			if result.isBlacklistedUA {
				userAgentBlacklistIPSet[result.request.IPUint32] = struct{}{}
			}
		}
		// Update the shared counts
		*invalidIPCount += localInvalidCount
		*uaWhitelistExcluded += localUAExcluded
		*filteredRequestCount += localFilteredCount
	}()

	// Distribute work in larger chunks to reduce overhead
	chunkSize := len(requests) / (numWorkers * 2) // 2 chunks per worker for better efficiency
	if chunkSize < 5000 {
		chunkSize = 5000 // Larger minimum chunk size
	}
	if chunkSize > 50000 {
		chunkSize = 50000 // Larger maximum chunk size
	}

	for i := 0; i < len(requests); i += chunkSize {
		end := i + chunkSize
		if end > len(requests) {
			end = len(requests)
		}

		requestChan <- requestChunk{
			requests: requests[i:end],
		}
	}
	close(requestChan)

	// Wait for all workers to complete
	wg.Wait()
	close(resultChan)

	// Wait for result collection to complete
	collectorWG.Wait()

	return nil
}

// filterRequests provides optimized sequential processing for simple filtering cases
func filterRequests(
	requests []ingestor.Request,
	trieConfig *config.TrieConfig,
	bounds timeBounds,
	userAgentMatcher *cidr.UserAgentMatcher,
	userAgentWhitelistIPSet, userAgentBlacklistIPSet map[uint32]struct{},
	filteredRequestCount *int,
	ipsToInsert *[]uint32,
	invalidIPCount *int,
	uaWhitelistExcluded *int) {

	// Single pass through requests with optimized filtering
	for _, r := range requests {
		// Apply time filtering
		if bounds.excluded(r.Timestamp) {
			continue
		}

		// Apply regex filtering
		if !trieConfig.ShouldIncludeRequest(r) {
			continue
		}

		// Skip 0 IPs (invalid or failed to parse)
		if r.IPUint32 == 0 {
			*invalidIPCount++
			continue
		}

		isWhitelistedUA := false
		isBlacklistedUA := false

		// Check User-Agent patterns using ultra-fast exact matching
		if userAgentMatcher != nil {
			uaResult := userAgentMatcher.CheckUserAgent(r.UserAgent)
			isWhitelistedUA = (uaResult == cidr.UserAgentWhitelist)
			isBlacklistedUA = (uaResult == cidr.UserAgentBlacklist)

			if isWhitelistedUA {
				userAgentWhitelistIPSet[r.IPUint32] = struct{}{}
			}
			if isBlacklistedUA {
				userAgentBlacklistIPSet[r.IPUint32] = struct{}{}
			}
		}

		// Include in trie if not whitelisted by User-Agent
		if !isWhitelistedUA {
			*ipsToInsert = append(*ipsToInsert, r.IPUint32)
			*filteredRequestCount++
		} else {
			*uaWhitelistExcluded++
		}
	}
}
