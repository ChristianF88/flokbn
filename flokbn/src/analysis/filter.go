package analysis

import (
	"time"

	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/ingestor"
)

// requestChunk represents a chunk of requests for parallel processing
type requestChunk struct {
	requests []ingestor.Request
	start    int
	end      int
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
	startTime, endTime time.Time,
	userAgentMatcher *cidr.UserAgentMatcher) {

	for chunk := range requestChan {
		for _, r := range chunk.requests {
			result := filterResult{
				request: r,
			}

			// Apply time filtering — skip rejected requests entirely (no channel send)
			if !startTime.IsZero() && r.Timestamp.Before(startTime) {
				continue
			}
			if !endTime.IsZero() && r.Timestamp.After(endTime) {
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
