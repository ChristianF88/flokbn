package analysis

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/iputils"
	"github.com/ChristianF88/flokbn/logparser"
	"github.com/ChristianF88/flokbn/output"
	"github.com/ChristianF88/flokbn/trie"
)

// Static runs static analysis from config and returns the same
// *output.JSONOutput as StaticWithRequests, without the parsed requests. When
// no trie filters on anything but the IP (no UA/endpoint/time filter, no
// User-Agent list) the log is parsed IP-only: no accesslog.Request is ever
// built, which cuts allocations sharply.
func Static(cfg *config.Config) (*output.JSONOutput, error) {
	jsonOutput, _, err := runStatic(context.Background(), cfg, false)
	return jsonOutput, err
}

// StaticWithRequests runs static analysis from config and also returns the parsed requests.
// It is a thin wrapper around StaticWithRequestsCtx using a background context
// (no cancellation), preserving the signature for the ~dozen existing call sites.
func StaticWithRequests(cfg *config.Config) (*output.JSONOutput, []accesslog.Request, error) {
	return StaticWithRequestsCtx(context.Background(), cfg)
}

// StaticWithRequestsCtx runs static analysis from config and also returns the
// parsed requests. The context provides coarse-grained cancellation for
// interactive callers (the TUI): cancelling it short-circuits before the heavy
// trie work materialises results and, critically, before the jail/ban-file side
// effects, so a quit-mid-analysis run never mutates on-disk state. The hot
// trie/clustering internals are NOT context-threaded (out of scope, and on the
// measured path); the checks in runStatic bracket the CPU-bound phase only.
func StaticWithRequestsCtx(ctx context.Context, cfg *config.Config) (*output.JSONOutput, []accesslog.Request, error) {
	return runStatic(ctx, cfg, true)
}

// runStatic is the static pipeline behind every entrypoint:
//
//	config checks -> list files -> parse -> one trie per [static.<name>]
//	(filter, build, CIDR-range stats, clustering) -> summary -> jail/ban publish
//
// keepRequests makes the parse step materialise and return every request even
// when no filter needs more than the IP (the TUI and the heatmap read them).
// Without it, and without filters, the parse step yields IPs only.
func runStatic(ctx context.Context, cfg *config.Config, keepRequests bool) (*output.JSONOutput, []accesslog.Request, error) {
	analysisStart := time.Now()
	jsonOutput := output.NewJSONOutput("static", analysisStart)

	if cfg == nil {
		jsonOutput.AddError("config_error", "configuration is nil", 1)
		return jsonOutput, nil, fmt.Errorf("configuration is nil")
	}

	if cfg.Static == nil {
		jsonOutput.AddError("config_error", "static configuration section is missing", 1)
		return jsonOutput, nil, fmt.Errorf("static configuration section is missing")
	}

	// Early cancellation check: bail before any parsing/trie work begins.
	if err := ctx.Err(); err != nil {
		return jsonOutput, nil, err
	}

	if len(cfg.StaticTries) == 0 {
		jsonOutput.AddWarning("config_warning", "no static tries configured, analysis may have limited results", 1)
	}

	logFormat := cfg.Static.LogFormat
	if logFormat == "" {
		logFormat = logparser.DefaultLogFormat
	}

	// NewParser revalidates the format as defense-in-depth; unreachable for a
	// barrier-passed config (config.Validate already ran logparser.ValidateFormat,
	// a total precondition for NewParser success), but it keeps a non-barrier
	// caller failing loud.
	parser, err := logparser.NewParser(logFormat)
	if err != nil {
		jsonOutput.AddError("parser_init", fmt.Sprintf("Failed to create parallel parser: %v", err), 1)
		return jsonOutput, nil, err
	}

	// The [global] list files are read once, here, and shared by every trie
	// and the publish step. A configured-but-unreadable UA whitelist/blacklist
	// file is a fatal setup error: continuing would skip ALL UA filtering and
	// persist a wrong ban file (UA-whitelisted IPs bannable, UA-blacklisted
	// bots not force-banned) on a "successful" exit. Fail loud BEFORE any trie
	// work or the jail/ban-file side effects below.
	lists, err := loadGlobalLists(cfg)
	if err != nil {
		jsonOutput.AddError("useragent_matcher_create", fmt.Sprintf("Failed to create User-Agent matcher: %v", err), 1)
		return jsonOutput, nil, err
	}

	// Which fields does any trie need beyond the IP? Strings (URI/User-Agent)
	// for the regex filters and the UA lists, the timestamp for time bounds.
	needsStringFields := false
	needsNonIPFields := false
	hasGlobalUAFilters := lists.uaMatcher.Count() > 0
	for _, tc := range cfg.StaticTries {
		if tc == nil {
			continue
		}
		if hasGlobalUAFilters || tc.UserAgentRegex != "" || tc.EndpointRegex != "" {
			needsStringFields = true
			needsNonIPFields = true
		}
		if tc.StartTime != nil || tc.EndTime != nil {
			needsNonIPFields = true
		}
	}
	parser.SkipStringFields = !needsStringFields
	parser.SkipNonIPFields = !needsNonIPFields

	// IP-only fast path: nobody reads anything but the IP, so the parser hands
	// back bare IPs and no accesslog.Request is built.
	ipOnly := !keepRequests && !needsNonIPFields

	parseStart := time.Now()
	parsed, err := parseLog(parser, cfg.Static.LogFile, ipOnly)
	parseDuration := time.Since(parseStart)
	if err != nil {
		jsonOutput.AddError("parse_file", fmt.Sprintf("Failed to parse log file %q: %v", cfg.Static.LogFile, err), 1)
		return jsonOutput, nil, err
	}

	// Lines longer than logparser.MaxLineLen are skipped by the parser, not
	// analysed: say so instead of dropping them silently.
	if n := parser.Stats().OversizedLines; n > 0 {
		jsonOutput.AddWarning("oversized_lines",
			fmt.Sprintf("%d line(s) longer than %d bytes were skipped", n, logparser.MaxLineLen), 1)
	}

	// Set general information
	jsonOutput.General.LogFile = cfg.Static.LogFile
	jsonOutput.General.TotalRequests = parsed.total
	jsonOutput.General.Parsing.DurationMS = parseDuration.Milliseconds()
	jsonOutput.General.Parsing.RatePerSecond = int64(float64(parsed.total) / parseDuration.Seconds())
	jsonOutput.General.Parsing.Format = logFormat

	// Surface malformed status/bytes fields (lines are KEPT with the field
	// zeroed; only the counts are reported). Structurally zero when
	// SkipNonIPFields is true (the parser then never scans status/bytes).
	if ps := parser.Stats(); ps.MalformedStatus > 0 || ps.MalformedBytes > 0 {
		if ps.MalformedStatus > 0 {
			jsonOutput.AddWarning("malformed_field",
				fmt.Sprintf("%d requests (%.1f%%) had a non-numeric status field (%%s) - status recorded as 0, lines kept",
					ps.MalformedStatus, float64(ps.MalformedStatus)/float64(parsed.total)*100), 1)
		}
		if ps.MalformedBytes > 0 {
			jsonOutput.AddWarning("malformed_field",
				fmt.Sprintf("%d requests (%.1f%%) had a non-numeric bytes field (%%b) - bytes recorded as 0, lines kept",
					ps.MalformedBytes, float64(ps.MalformedBytes)/float64(parsed.total)*100), 1)
		}
	}

	if parsed.total == 0 {
		jsonOutput.AddWarning("empty_logfile", "No requests found in logfile", 1)
		// Nothing to analyse, but the publish step still has work: bans that ran
		// out since the last run must leave the ban file, and whitelist/blacklist
		// edits must be picked up. A cancelled (quit) TUI run must not mutate
		// on-disk jail/ban state.
		if err := ctx.Err(); err != nil {
			return jsonOutput, parsed.requests, err
		}
		if err := publishJailAndBans(cfg, lists, jsonOutput); err != nil {
			return jsonOutput, parsed.requests, err
		}
		return jsonOutput, parsed.requests, nil
	}

	// The log's sorted IPs feed general.unique_ips and every trie without
	// filters. When no trie filters, every trie starts from them: sort before
	// the trie phase. Otherwise sort in the background while the tries with
	// filters select their requests; joined right after the trie phase.
	if !needsNonIPFields {
		parsed.sortedIPs()
	} else {
		go parsed.sortedIPs()
	}

	trieResults, uaWhitelistIPs, uaBlacklistIPs := runTries(cfg.StaticTries, parsed, lists.uaMatcher, jsonOutput)

	// General.UniqueIPs describes the whole log (distinct client IPs across all
	// parsed requests), independent of any trie's filters.
	_, generalUniqueIPs := parsed.sortedIPs()

	// Cancellation check after the CPU-bound trie phase, before the jail/ban-file
	// side effects below. A cancelled (quit) TUI run must not mutate on-disk
	// jail/ban state.
	if err := ctx.Err(); err != nil {
		return jsonOutput, parsed.requests, err
	}

	jsonOutput.Tries = trieResults

	// Record the global whitelist entry counts. Only the UA whitelist is a real
	// request filter (it drops requests from every trie) and is listed under
	// Active Filters; the IP whitelist count is informational only - it filters
	// nothing here (jail/ban publish pipeline only).
	jsonOutput.GlobalFilters = lists.globalFilters()

	jsonOutput.General.UniqueIPs = generalUniqueIPs

	// Publish the User-Agent derived IPs (also the input of the jail step below)
	// in a stable order: ascending by address, each IP once.
	jsonOutput.UserAgentWhitelistIPs = sortedUniqueIPStrings(uaWhitelistIPs)
	jsonOutput.UserAgentBlacklistIPs = sortedUniqueIPStrings(uaBlacklistIPs)

	// Process jail with whitelist/blacklist if configured
	if err := publishJailAndBans(cfg, lists, jsonOutput); err != nil {
		return jsonOutput, parsed.requests, err
	}

	jsonOutput.UpdateDuration(analysisStart)
	return jsonOutput, parsed.requests, nil
}

// parsedLog is the outcome of the parse step and the IP source of the trie
// phase. It comes in two shapes:
//
//   - full: requests holds every parsed line. Tries with filters select from
//     it; the sorted IP list for the others is derived from it on first use.
//   - IP-only: requests is nil and the parser delivered the nonzero IPs
//     directly. Only possible when no trie has a filter.
type parsedLog struct {
	requests []accesslog.Request
	// total is the number of parsed lines, including those without a usable IP.
	total int

	// ipOnly marks the IP-only shape: ips came from the parser. Otherwise
	// sortedIPs extracts them from requests.
	ipOnly bool

	sortOnce  sync.Once
	ips       []uint32 // after sortOnce: every nonzero IP, ascending
	uniqueIPs int      // after sortOnce: distinct values in ips
}

// parseLog reads the log file, IP-only or in full.
func parseLog(parser *logparser.Parser, logFile string, ipOnly bool) (*parsedLog, error) {
	if ipOnly {
		ips, invalidCount, err := parser.ParseFileIPs(logFile)
		if err != nil {
			return nil, err
		}
		// total must equal len(requests) of a full parse: all parsed lines,
		// i.e. nonzero IPs (len(ips)) plus zero-IP lines (invalidCount).
		return &parsedLog{ipOnly: true, ips: ips, total: len(ips) + invalidCount}, nil
	}

	requests, err := parser.ParseFile(logFile)
	if err != nil {
		return nil, err
	}
	return &parsedLog{requests: requests, total: len(requests)}, nil
}

// sortedIPs returns the nonzero client IP of every parsed line in ascending
// order (one entry per request, so total-len(ips) lines had no usable IP) and
// the number of distinct IPs among them.
//
// The slice is computed once - radix sort, O(n) - and shared by every caller:
// it is the build input of each trie without filters and must not be modified.
// Safe for concurrent use; concurrent callers wait for the one computation.
func (l *parsedLog) sortedIPs() (ips []uint32, uniqueIPs int) {
	l.sortOnce.Do(func() {
		if !l.ipOnly {
			// Zero IPs (invalid/unparseable host field) are left out, as the
			// IP-only parse leaves them out.
			l.ips = make([]uint32, 0, len(l.requests))
			for i := range l.requests {
				if ip := l.requests[i].IPUint32; ip != 0 {
					l.ips = append(l.ips, ip)
				}
			}
		}
		iputils.RadixSortUint32(l.ips)
		l.uniqueIPs = iputils.CountDistinctSorted(l.ips)
	})
	return l.ips, l.uniqueIPs
}

// runTries builds and analyses every configured trie, several at a time, and
// returns the results sorted by trie name. It also returns the IPs seen with a
// whitelisted / blacklisted User-Agent, merged over all tries (unsorted, an IP
// may repeat).
func runTries(tries map[string]*config.TrieConfig, parsed *parsedLog, userAgentMatcher *cidr.UserAgentMatcher,
	jsonOutput *output.JSONOutput) (trieResults []output.TrieResult, uaWhitelistIPs, uaBlacklistIPs []uint32) {

	type trieWork struct {
		name   string
		config *config.TrieConfig
	}

	var trieWG sync.WaitGroup
	var triesMutex sync.Mutex // guards the three result slices
	trieResults = make([]output.TrieResult, 0, len(tries))

	trieWorkChan := make(chan trieWork, len(tries))

	numTrieWorkers := runtime.NumCPU()
	if len(tries) < numTrieWorkers {
		numTrieWorkers = len(tries)
	}

	for i := 0; i < numTrieWorkers; i++ {
		trieWG.Add(1)
		go func() {
			defer trieWG.Done()

			for work := range trieWorkChan {
				result, whitelistIPs, blacklistIPs := processTrie(work.name, work.config, parsed, userAgentMatcher, jsonOutput)

				triesMutex.Lock()
				trieResults = append(trieResults, result)
				uaWhitelistIPs = append(uaWhitelistIPs, whitelistIPs...)
				uaBlacklistIPs = append(uaBlacklistIPs, blacklistIPs...)
				triesMutex.Unlock()
			}
		}()
	}

	for trieName, trieConfig := range tries {
		trieWorkChan <- trieWork{name: trieName, config: trieConfig}
	}
	close(trieWorkChan)
	trieWG.Wait()

	// Workers finish in any order; the output lists tries by name.
	sort.Slice(trieResults, func(i, j int) bool {
		return trieResults[i].Name < trieResults[j].Name
	})
	return trieResults, uaWhitelistIPs, uaBlacklistIPs
}

// sortedUniqueIPStrings sorts ips ascending (in place), drops duplicates and
// renders the dotted-quad strings. Returns nil for an empty input so the JSON
// field stays omitted.
func sortedUniqueIPStrings(ips []uint32) []string {
	if len(ips) == 0 {
		return nil
	}
	iputils.RadixSortUint32(ips)
	out := make([]string, 0, iputils.CountDistinctSorted(ips))
	for i, ip := range ips {
		if i > 0 && ip == ips[i-1] {
			continue
		}
		out = append(out, accesslog.Uint32ToIPString(ip))
	}
	return out
}

// processTrie builds and analyzes a single trie; runTries runs several at once.
// Returns the trie result along with the IPs this trie saw with a whitelisted /
// blacklisted User-Agent (numeric, unspecified order, an IP may repeat - the
// caller merges, sorts and de-duplicates them across tries).
//
// The trie's IPs come from one of two sources: without filters, the log's
// shared sorted IP list (parsedLog.sortedIPs); with filters, the requests that pass
// them. userAgentMatcher is built once by the caller and shared across all
// tries (it depends only on global config).
func processTrie(trieName string, trieConfig *config.TrieConfig, parsed *parsedLog,
	userAgentMatcher *cidr.UserAgentMatcher, jsonOutput *output.JSONOutput) (output.TrieResult, []uint32, []uint32) {

	insertStart := time.Now()

	trieResult := output.TrieResult{
		Name:       trieName,
		Parameters: output.TrieParameters{},
		Stats:      output.TrieStats{},
		Data:       []output.ClusterResult{},
	}

	if trieConfig == nil {
		jsonOutput.AddWarning("config_warning", fmt.Sprintf("Trie configuration %q is nil, skipping", trieName), 1)
		return trieResult, nil, nil
	}

	// Malformed/inverted startTime/endTime are caught at config load and
	// reported by the pre-work barrier (CFG-01), which fails loud before analysis
	// runs. The time_filter_no_results warning below is a RUNTIME observation on
	// VALIDLY-parsed bounds.

	// Set CIDRRanges after null check
	trieResult.Parameters.CIDRRanges = trieConfig.CIDRRanges

	// The raw start/end times feed the TimeRange output below; the filter
	// compares through makeTimeBounds, which carries the URGENT-09
	// wall-clock-vs-instant semantics.
	var startTime, endTime time.Time
	if trieConfig.StartTime != nil {
		startTime = *trieConfig.StartTime
	}
	if trieConfig.EndTime != nil {
		endTime = *trieConfig.EndTime
	}

	// Add regex filters to parameters if they exist
	if trieConfig.UserAgentRegex != "" {
		trieResult.Parameters.UserAgentRegex = &trieConfig.UserAgentRegex
	}
	if trieConfig.EndpointRegex != "" {
		trieResult.Parameters.EndpointRegex = &trieConfig.EndpointRegex
	}

	// Add time range to parameters if set
	if !startTime.IsZero() || !endTime.IsZero() {
		trieResult.Parameters.TimeRange = &output.TimeRange{
			Start: startTime,
			End:   endTime,
		}
	}

	// Add UseForJail configuration if set
	if len(trieConfig.UseForJail) > 0 {
		trieResult.Parameters.UseForJail = trieConfig.UseForJail
	}

	// Check if we have any filters that require per-request processing.
	// Only consider User-Agent matcher a filter if it actually has patterns.
	// Any filter found here also forced the full parse in runStatic (its
	// needsNonIPFields test is a superset), so parsed.requests is there to filter.
	hasUserAgentFilters := userAgentMatcher != nil && userAgentMatcher.Count() > 0
	hasFilters := hasUserAgentFilters ||
		trieConfig.UserAgentRegex != "" ||
		trieConfig.EndpointRegex != "" ||
		!startTime.IsZero() ||
		!endTime.IsZero()

	var (
		// The trie's build input: ascending, one entry per request that is
		// inserted. Only its length is consumed besides the build
		// (TotalRequestsAfterFiltering and the zero-result time warning).
		ips []uint32
		// True unique-IP count, derived from the sorted slice in a single linear
		// pass - keeps the trie insert hot path untouched.
		uniqueIPs int
		// Requests skipped for an invalid/missing IP.
		invalidIPCount int
		// Requests dropped solely because their User-Agent matched the global UA
		// whitelist (surfaced in the summary so the request-count drop is never
		// unexplained when no per-trie filters are active).
		uaWhitelistExcluded int
		// IPs seen with a whitelisted / blacklisted User-Agent.
		userAgentWhitelistIPs, userAgentBlacklistIPs []uint32
	)

	if !hasFilters {
		// No filters: every nonzero IP of the log, sorted once and shared with
		// the other unfiltered tries (read-only).
		ips, uniqueIPs = parsed.sortedIPs()
		invalidIPCount = parsed.total - len(ips)
	} else {
		// One filter pass (concurrent for large logs, see filterRequests), then
		// the same radix sort the shared list gets.
		filtered := filterRequests(parsed.requests, trieConfig, makeTimeBounds(trieConfig), userAgentMatcher)
		iputils.RadixSortUint32(filtered.ips)
		ips = filtered.ips
		uniqueIPs = iputils.CountDistinctSorted(ips)
		invalidIPCount = filtered.invalid
		uaWhitelistExcluded = filtered.uaExcluded
		userAgentWhitelistIPs = filtered.uaWhitelistIPs
		userAgentBlacklistIPs = filtered.uaBlacklistIPs
	}

	// The trie is built by this goroutine alone, from ascending input, so the
	// lock-free sequential allocator and the prefix-stack build apply
	// (bit-identical to InsertSorted, ~2x faster).
	trieInstance := trie.NewLockedTrieSeq()
	trieInstance.BuildSorted(ips)

	insertDuration := time.Since(insertStart)

	// Add warning if invalid IPs were skipped. Emitted per trie and naming the
	// trie: the count depends on the trie's filters.
	if invalidIPCount > 0 {
		percentage := float64(invalidIPCount) / float64(parsed.total) * 100
		jsonOutput.AddWarning("invalid_ips_skipped",
			fmt.Sprintf("Trie %q: %d requests (%.1f%%) had invalid/missing IPs (nil or 0.0.0.0) and were skipped - check log format", trieName, invalidIPCount, percentage), 1)
	}

	// Set trie stats
	trieResult.Stats = output.TrieStats{
		TotalRequestsAfterFiltering: len(ips),
		UniqueIPs:                   uniqueIPs,
		SkippedInvalidIPs:           invalidIPCount,
		UAWhitelistExcluded:         uaWhitelistExcluded,
		InsertTimeMS:                insertDuration.Milliseconds(),
	}

	// Warn if time filter resulted in zero requests (non-overlapping time range)
	if len(ips) == 0 && (!startTime.IsZero() || !endTime.IsZero()) {
		var timeRangeStr string
		if !startTime.IsZero() && !endTime.IsZero() {
			timeRangeStr = fmt.Sprintf("%s to %s", startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))
		} else if !startTime.IsZero() {
			timeRangeStr = fmt.Sprintf("after %s", startTime.Format(time.RFC3339))
		} else {
			timeRangeStr = fmt.Sprintf("before %s", endTime.Format(time.RFC3339))
		}
		jsonOutput.AddWarning("time_filter_no_results",
			fmt.Sprintf("Trie %q: time filter %q resulted in 0 requests - the time range may not overlap with log data",
				trieName, timeRangeStr), 1)
	}

	// CIDR range analysis
	if len(trieConfig.CIDRRanges) > 0 {
		for _, cidrRange := range trieConfig.CIDRRanges {
			count, err := trieInstance.CountInRange(cidrRange)
			if err != nil {
				jsonOutput.AddWarning("invalid_cidr", fmt.Sprintf("Invalid CIDR range %q: %v", cidrRange, err), 1)
				continue
			}

			var percentage float64
			if trieInstance.CountAll() > 0 {
				percentage = float64(count) / float64(trieInstance.CountAll()) * 100
			}
			trieResult.Stats.CIDRAnalysis = append(trieResult.Stats.CIDRAnalysis, output.CIDRRange{
				CIDR:       cidrRange,
				Requests:   count,
				Percentage: percentage,
			})
		}
	}

	// Clustering
	processClustering(trieConfig, trieInstance.Trie, jsonOutput, &trieResult)

	return trieResult, userAgentWhitelistIPs, userAgentBlacklistIPs
}

func processClustering(trieConfig *config.TrieConfig, trieInstance *trie.Trie,
	jsonOutput *output.JSONOutput, trieResult *output.TrieResult) {
	// Implementation same as original
	if len(trieConfig.ClusterArgSets) == 0 {
		return
	}

	for _, argSet := range trieConfig.ClusterArgSets {
		// TrieResult.Data must hold exactly one entry per configured arg set, in
		// config order: the publish step (jailCandidates) pairs Data[i] with UseForJail[i]
		// by position (and the renderers number the sets the same way). An
		// invalid set therefore still gets an entry - an empty placeholder with
		// its parameters - instead of being skipped, which would shift every
		// later set onto its left neighbour's useForJail flag.
		clusterResult := output.ClusterResult{
			Parameters: output.ClusterParameters{
				MinClusterSize:       argSet.MinClusterSize,
				MinDepth:             argSet.MinDepth,
				MaxDepth:             argSet.MaxDepth,
				MeanSubnetDifference: argSet.MeanSubnetDifference,
			},
			DetectedRanges: []output.CIDRRange{},
			MergedRanges:   []output.CIDRRange{},
		}

		if argSet.MinDepth > argSet.MaxDepth {
			jsonOutput.AddError("invalid_depth_params",
				fmt.Sprintf("minDepth (%d) must be <= maxDepth (%d)", argSet.MinDepth, argSet.MaxDepth), 1)
			trieResult.Data = append(trieResult.Data, clusterResult)
			continue
		}
		if argSet.MaxDepth > 32 {
			jsonOutput.AddError("invalid_depth_params",
				fmt.Sprintf("maxDepth (%d) must be <= 32", argSet.MaxDepth), 1)
			trieResult.Data = append(trieResult.Data, clusterResult)
			continue
		}

		clusterStart := time.Now()
		cidrs := trieInstance.CollectCIDRs(argSet.MinClusterSize, argSet.MinDepth, argSet.MaxDepth, argSet.MeanSubnetDifference)
		clusterResult.ExecutionTimeUS = time.Since(clusterStart).Microseconds()

		// Parse CIDRs once for reuse across operations
		var cidrIPNets []*net.IPNet
		// CountAll counts every insertion (duplicate IPs included), so this is
		// the request total - percentages below are percent-of-requests.
		totalRequests := float64(trieInstance.CountAll())

		for _, cidrStr := range cidrs {
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				jsonOutput.AddWarning("cidr_parse_error",
					fmt.Sprintf("Error parsing CIDR %q: %v", cidrStr, err), 1)
				continue
			}
			cidrIPNets = append(cidrIPNets, ipNet)

			// Use IPNet-native count function for speed
			count := trieInstance.CountInRangeIPNet(ipNet)
			var percentage float64
			if totalRequests > 0 {
				percentage = float64(count) / totalRequests * 100
			}

			clusterResult.DetectedRanges = append(clusterResult.DetectedRanges, output.CIDRRange{
				CIDR:       cidrStr,
				Requests:   count,
				Percentage: percentage,
			})
		}

		// Use IPNet-native merge function to avoid re-parsing
		mergedIPNets := cidr.MergeIPNets(cidrIPNets)
		for _, mergedIPNet := range mergedIPNets {
			count := trieInstance.CountInRangeIPNet(mergedIPNet)
			var percentage float64
			if totalRequests > 0 {
				percentage = float64(count) / totalRequests * 100
			}

			clusterResult.MergedRanges = append(clusterResult.MergedRanges, output.CIDRRange{
				CIDR:       mergedIPNet.String(),
				Requests:   count,
				Percentage: percentage,
			})
		}

		trieResult.Data = append(trieResult.Data, clusterResult)
	}
}
