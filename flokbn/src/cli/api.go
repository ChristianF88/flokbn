package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ChristianF88/flokbn/analysis"
	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/iputils"
	"github.com/ChristianF88/flokbn/jail"
	"github.com/ChristianF88/flokbn/output"
	"github.com/ChristianF88/flokbn/sliding"
	"github.com/ChristianF88/flokbn/tui"
	"github.com/ChristianF88/flokbn/version"
)

// ============================================================================
// CONFIGURATION STRUCTS
// ============================================================================

// Note: Using config.LiveConfig instead of defining our own

// OutputConfig contains output formatting options
type OutputConfig struct {
	Compact bool
	Plain   bool
	TUI     bool
}

// ============================================================================
// MAIN ENTRY POINTS - These are the only functions that should be called externally
// ============================================================================

// StaticFromConfig runs static analysis from a Config struct
func StaticFromConfig(cfg *config.Config, compact, plain, tui bool) error {
	outputConfig := OutputConfig{
		Compact: compact,
		Plain:   plain,
		TUI:     tui,
	}

	// Use the same execution path regardless of input source
	return executeStaticAnalysis(cfg, outputConfig)
}

// ============================================================================
// CORE EXECUTION LOGIC - Single unified execution path
// ============================================================================

// executeStaticAnalysis handles all static analysis - CLI or config file, doesn't matter
func executeStaticAnalysis(cfg *config.Config, outputConfig OutputConfig) error {
	// Route to TUI if requested
	if outputConfig.TUI {
		return executeTUI(cfg)
	}

	// No heatmap requested: take the IP-only fast path that never materialises
	// the []ingestor.Request slice (the requests would otherwise be discarded).
	if cfg.Static == nil || cfg.Static.PlotPath == "" {
		result, err := analysis.Static(cfg)
		if err != nil {
			outputResult(result, outputConfig) // Output with errors
			return fmt.Errorf("static analysis: %w", err)
		}
		outputResult(result, outputConfig)
		return nil
	}

	// Heatmap requested: keep the full path so we can reuse the parsed requests.
	result, requests, err := analysis.StaticWithRequests(cfg)
	if err != nil {
		outputResult(result, outputConfig) // Output with errors
		return fmt.Errorf("static analysis: %w", err)
	}

	// Generate heatmap if plotPath is provided - reuse parsed requests
	if requests != nil {
		plotStart := time.Now()
		if err := output.PlotHeatmap(requests, cfg.Static.PlotPath); err != nil {
			result.AddError("heatmap", fmt.Sprintf("failed to generate heatmap: %v", err), 1)
		} else {
			plotDuration := time.Since(plotStart)
			result.AddWarning("info", fmt.Sprintf("Heatmap generated in %v at %s", plotDuration, cfg.Static.PlotPath), 0)
		}
	}

	outputResult(result, outputConfig)
	return nil
}

// executeTUI runs TUI mode - works for both CLI and config file inputs
func executeTUI(cfg *config.Config) error {
	app := tui.NewAppFromConfig(cfg, "")

	// Tie the analysis goroutine's lifetime to the TUI: cancelling when app.Run
	// returns stops the analysis short-circuiting before its jail/ban-file side
	// effects, and the ctx guards below make the app setters no-ops once the TUI
	// has exited (so a late-finishing analysis never drives a stopped app).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run the complete analysis first (like non-TUI mode), then pass results to TUI
	go func() {
		// Do the same complete analysis as non-TUI mode
		multiTrieResult, requests, err := analysis.StaticWithRequestsCtx(ctx, cfg)
		if err != nil {
			// The TUI has already exited (quit mid-analysis): nothing to show.
			if ctx.Err() != nil {
				return
			}
			// Show error in TUI instead of silent failure
			app.ShowError(fmt.Sprintf("Analysis failed: %v", err))
			return
		}

		// TUI exited while the analysis was finishing: do not drive a stopped app.
		if ctx.Err() != nil {
			return
		}

		// Verify we got results
		if multiTrieResult == nil {
			app.ShowError("Analysis completed but returned no results")
			return
		}

		// Set the complete analysis results first
		app.SetAnalysisResults(multiTrieResult)

		// Then set raw requests for visualization
		if requests != nil {
			app.SetRequestData(requests)
		}
	}()

	if err := app.Run(); err != nil {
		return fmt.Errorf("TUI: %w", err)
	}
	return nil
}

// ============================================================================
// LIVE MODE IMPLEMENTATION
// ============================================================================

// LiveFromConfig runs live mode from a Config struct
func LiveFromConfig(cfg *config.Config) error {
	return executeLiveAnalysis(cfg)
}

// slidingWindowInstance holds a sliding window and its associated configuration
type slidingWindowInstance struct {
	name   string
	window *sliding.SlidingWindow
	config *config.SlidingTrieConfig

	// Lifetime counters, owned by the loop goroutine (no atomics needed).
	acceptedTotal uint64
	rejectedTotal uint64 // ShouldIncludeRequest rejections; zero-ts/IP skips excluded
}

// executeLiveAnalysis runs live mode analysis - works for both CLI and config file inputs
func executeLiveAnalysis(cfg *config.Config) error {
	if len(cfg.LiveTries) == 0 {
		return fmt.Errorf("no LiveTries configurations found")
	}

	logger := slog.Default()

	ing, err := ingestor.NewTCPIngestor(
		":"+cfg.Live.Port,
		cfg.GetReadTimeout(), // read timeout: avoid client disconnects
	)

	if err != nil {
		return fmt.Errorf("creating ingestor: %w", err)
	}
	// Free the bound listener on every early return below (whitelist/blacklist/
	// UA list/jail load failures all return before runLiveLoop reaches Accept,
	// which is where the cancellation watcher's Close lives). Close is
	// idempotent via closeOnce and tolerates server==nil, so this collapses with
	// the watcher's Close on the normal path — no double-close.
	defer ing.Close()

	totalClusterSets := 0
	for _, trie := range cfg.LiveTries {
		totalClusterSets += len(trie.ClusterArgSets)
	}
	logger.Info("starting live loop",
		"version", version.Version,
		"listen", ":"+cfg.Live.Port,
		"jail_file", cfg.GetJailFile(),
		"ban_file", cfg.GetBanFile(),
		"windows", len(cfg.LiveTries),
		"cluster_sets", totalClusterSets,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	go func() {
		select {
		case <-stop:
			logger.Info("received shutdown signal")
			cancel()
		case <-ctx.Done():
		}
	}()

	stats, err := newStatsServerFromConfig(cfg)
	if err != nil {
		return fmt.Errorf("stats server: %w", err)
	}
	if stats != nil {
		stats.start()
		defer stats.shutdown()
		logger.Info("stats server listening", "addr", stats.addr())
	}

	return runLiveLoop(ctx, ing, cfg, logger, stats)
}

// newStatsServerFromConfig binds the stats listener when [live] statsListen
// is set; nil server means the feature is off (zero additional loop cost).
func newStatsServerFromConfig(cfg *config.Config) (*statsServer, error) {
	if cfg.Live == nil || cfg.Live.StatsListen == "" {
		return nil, nil
	}
	return newStatsServer(cfg.Live.StatsListen)
}

// purgeExpired drops entries last seen before cutoff (window-aligned expiry
// for the User-Agent list IP sets).
func purgeExpired(m map[uint32]time.Time, cutoff time.Time) {
	for ip, seen := range m {
		if seen.Before(cutoff) {
			delete(m, ip)
		}
	}
}

const (
	// liveHeartbeatFloor is the minimum idle-heartbeat interval. The
	// heartbeat normally fires every maxSleepTime seconds, but configs with
	// SleepBetweenIterations 0 (tests, aggressive setups) still need bans to
	// expire and snapshots to advance during zero-traffic stretches.
	liveHeartbeatFloor = time.Second
	// liveIdlePoll is how long the loop sleeps after an empty ReadBatch
	// before polling again (ReadBatch is non-blocking).
	liveIdlePoll = time.Second
)

// sleepOrDone sleeps for d, returning early when ctx is cancelled.
func sleepOrDone(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// runLiveLoop is the context-cancellable core of live mode. logger receives
// leveled progress/diagnostic lines (production: the process-wide slog logger
// on stderr); machine-readable data is served by the stats server endpoints.
// Cancelling ctx closes the ingestor, which makes the loop exit cleanly.
// stats is optional: when non-nil the loop publishes an immutable snapshot
// to it after each full iteration (nil = feature off, zero extra work).
func runLiveLoop(ctx context.Context, ing ingestor.Ingestor, cfg *config.Config, logger *slog.Logger, stats *statsServer) error {
	if len(cfg.LiveTries) == 0 {
		return fmt.Errorf("no LiveTries configurations found")
	}

	// Create sliding window instances - one per LiveTries entry
	var windows []slidingWindowInstance
	for name, slidingConfig := range cfg.LiveTries {
		window := sliding.NewSlidingWindowTrie(
			slidingConfig.SlidingWindowMaxTime,
			slidingConfig.SlidingWindowMaxSize,
		)
		windows = append(windows, slidingWindowInstance{
			name:   name,
			window: window,
			config: slidingConfig,
		})
	}

	// Load whitelist/blacklist once at startup, mirroring static mode's
	// ProcessJailWithWhitelist semantics. A broken list config fails loud
	// instead of silently banning whitelisted ranges.
	whitelistCIDRs, err := cfg.LoadWhitelistCIDRs()
	if err != nil {
		return fmt.Errorf("loading whitelist: %w", err)
	}
	blacklistCIDRs, err := cfg.LoadBlacklistCIDRs()
	if err != nil {
		return fmt.Errorf("loading blacklist: %w", err)
	}

	// User-Agent lists (static parity): exact case-insensitive matching via
	// the same matcher static mode uses. Broken list files fail loud at
	// startup, like the CIDR lists above.
	uaWhitelistPatterns, err := cfg.LoadUserAgentWhitelistPatterns()
	if err != nil {
		return fmt.Errorf("loading user-agent whitelist: %w", err)
	}
	uaBlacklistPatterns, err := cfg.LoadUserAgentBlacklistPatterns()
	if err != nil {
		return fmt.Errorf("loading user-agent blacklist: %w", err)
	}
	var uaMatcher *cidr.UserAgentMatcher
	if len(uaWhitelistPatterns) > 0 || len(uaBlacklistPatterns) > 0 {
		uaMatcher = cidr.NewUserAgentMatcher(uaWhitelistPatterns, uaBlacklistPatterns)
		logger.Info("user-agent lists loaded",
			"whitelist_patterns", len(uaWhitelistPatterns),
			"blacklist_patterns", len(uaBlacklistPatterns),
		)
	}
	// IPs seen with listed User-Agents, with last-seen times. Purged after
	// the largest window duration each iteration, so memory stays bounded by
	// the unique listed IPs per window.
	uaWhitelistIPs := make(map[uint32]time.Time)
	uaBlacklistIPs := make(map[uint32]time.Time)

	jailInstance, err := jail.FileToJail(cfg.GetJailFile())
	if err != nil {
		return fmt.Errorf("reading jail file: %w", err)
	}

	var statsState *liveStatsState
	if stats != nil {
		statsState = newLiveStatsState(cfg, whitelistCIDRs, blacklistCIDRs)
	}

	logger.Info("waiting for Filebeat to connect")

	if err := ing.Accept(); err != nil {
		return fmt.Errorf("accepting connection: %w", err)
	}

	logger.Info("Filebeat connected")

	// Cancellation watcher: closing the ingestor unblocks the loop below.
	// Started only after Accept so ing's internal state is never written
	// concurrently with Close.
	loopDone := make(chan struct{})
	defer close(loopDone)
	go func() {
		select {
		case <-ctx.Done():
			ing.Close()
		case <-loopDone:
		}
	}()

	// Calculate maximum sleep time and window duration across all windows
	maxSleepTime := 0
	maxWindowTime := time.Duration(0)
	for _, winInst := range windows {
		if winInst.config.SleepBetweenIterations > maxSleepTime {
			maxSleepTime = winInst.config.SleepBetweenIterations
		}
		if winInst.config.SlidingWindowMaxTime > maxWindowTime {
			maxWindowTime = winInst.config.SlidingWindowMaxTime
		}
	}

	// blacklist_applied is emitted once per run, on the first successful
	// ban-file write (static emits it once per analysis).
	blacklistWarned := false

	// Idle-heartbeat state. ReadBatch is non-blocking, so during zero-traffic
	// stretches the loop must still expire jail bans, refresh the ban file,
	// and publish snapshots — otherwise bans never lift (lockout feedback
	// loop) and /stats freezes. lastTick is the last time either a full
	// iteration or a heartbeat ran.
	heartbeatInterval := time.Duration(maxSleepTime) * time.Second
	if heartbeatInterval < liveHeartbeatFloor {
		heartbeatInterval = liveHeartbeatFloor
	}
	lastTick := time.Now()
	// Change-detection key for the published ban lists; invalid until the
	// first successful ban-file write, so the first heartbeat always syncs
	// the file once (recovers from a stale ban file on disk).
	var lastBanKey string
	banKeyValid := false
	// Last iteration's per-window cluster stats, re-served by heartbeat
	// snapshots (no traffic means no new clustering result).
	var lastWinClusterStats [][]clusterSetStats

	for {
		loopStart := time.Now()

		batch, err := ing.ReadBatch()
		if err != nil {
			return fmt.Errorf("reading batch: %w", err)
		}

		if len(batch) == 0 {
			if ing.IsClosed() {
				logger.Info("ingestor closed, exiting loop")
				break
			}
			sleepOrDone(ctx, liveIdlePoll)
			if time.Since(lastTick) >= heartbeatInterval {
				// Window-aligned expiry must run on the idle path too, before
				// runHeartbeat composes whitelists: otherwise a stale UA-
				// whitelisted /32 keeps suppressing an active jail ban for the
				// whole idle stretch (it never re-appears until traffic
				// resumes). Mirrors the batch branch exactly; maps are shared
				// by reference, so this mutates what runHeartbeat reads.
				if uaMatcher != nil {
					cutoff := time.Now().Add(-maxWindowTime)
					purgeExpired(uaWhitelistIPs, cutoff)
					purgeExpired(uaBlacklistIPs, cutoff)
				}
				runHeartbeat(&jailInstance, cfg, logger, stats, statsState, ing,
					windows, lastWinClusterStats, whitelistCIDRs, uaWhitelistIPs,
					blacklistCIDRs, &lastBanKey, &banKeyValid, &blacklistWarned,
					maxSleepTime)
				lastTick = time.Now()
			}
			continue
		}

		if logger.Enabled(ctx, slog.LevelDebug) {
			ingSt := ing.Stats()
			logger.Debug("batch read",
				"size", len(batch),
				"queue_depth", ingSt.QueueDepth,
				"parse_errors_total", ingSt.ParseErrorsTotal,
				"malformed_fields_total", ingSt.MalformedFieldsTotal,
			)
		}

		// Classify User-Agents once per batch (lists are global, not
		// per-window). Whitelisted-UA requests never enter any window
		// (parity with static trie exclusion) and immunize their IP at
		// publish time; blacklisted-UA IPs are force-jailed as /32 below.
		if uaMatcher != nil {
			now := time.Now()
			kept := batch[:0]
			for _, msg := range batch {
				switch uaMatcher.CheckUserAgent(msg.UserAgent) {
				case cidr.UserAgentWhitelist:
					if msg.IPUint32 != 0 {
						uaWhitelistIPs[msg.IPUint32] = now
					}
					if statsState != nil {
						statsState.uaWhitelistHits++
					}
					continue
				case cidr.UserAgentBlacklist:
					if msg.IPUint32 != 0 {
						uaBlacklistIPs[msg.IPUint32] = now
					}
					if statsState != nil {
						statsState.uaBlacklistHits++
					}
				}
				kept = append(kept, msg)
			}
			batch = kept

			// Window-aligned expiry keeps both sets bounded.
			cutoff := now.Add(-maxWindowTime)
			purgeExpired(uaWhitelistIPs, cutoff)
			purgeExpired(uaBlacklistIPs, cutoff)
		}

		// Collect all CIDRs to ban from all sliding windows
		var allMergedCIDRs []*net.IPNet
		var allDetectedCIDRs []output.LiveCIDR
		totalClusterDuration := int64(0)
		totalWindowSize := 0

		// Per-window per-set snapshot data, built only when stats is enabled.
		var winClusterStats [][]clusterSetStats
		if stats != nil {
			winClusterStats = make([][]clusterSetStats, len(windows))
		}

		// Process each sliding window (by pointer: lifetime counters persist)
		for wi := range windows {
			winInst := &windows[wi]
			// Filter batch based on this window's regex filters
			timedIps := make([]sliding.TimedIP, 0, len(batch))
			for _, msg := range batch {
				if msg.Timestamp.IsZero() || msg.IPUint32 == 0 {
					continue
				}

				// Apply regex filtering based on window config
				if !winInst.config.ShouldIncludeRequest(msg) {
					winInst.rejectedTotal++
					continue
				}

				// Carry the already-validated IPv4 value as uint32 directly
				// (AUDIT-05). msg.IPUint32 is the upstream-validated IP
				// (IPv6/non-To4 rejected at the ingestor, 0 = reject sentinel,
				// and IPUint32==0 is filtered just above), so this avoids the
				// per-request net.IPv4 heap allocation that GetIPNet() incurred
				// plus the redundant IPToUint32 round-trips in the window.
				timedIps = append(timedIps, sliding.TimedIP{
					IP:   msg.IPUint32,
					Time: msg.Timestamp,
				})
			}
			winInst.acceptedTotal += uint64(len(timedIps))

			// Update this specific window
			winInst.window.Update(timedIps)
			totalWindowSize += len(winInst.window.IPQueue)

			// Run clustering for each ClusterArgSet on this window
			for i, argSet := range winInst.config.ClusterArgSets {
				useForJail := false
				if i < len(winInst.config.UseForJail) {
					useForJail = winInst.config.UseForJail[i]
				}

				clusterStart := time.Now()
				cidrs := winInst.window.Trie.CollectCIDRs(
					argSet.MinClusterSize,
					argSet.MinDepth,
					argSet.MaxDepth,
					argSet.MeanSubnetDifference,
				)
				clusterDuration := time.Since(clusterStart)
				totalClusterDuration += clusterDuration.Microseconds()

				// Parse CIDRs once for reuse across operations
				var cidrIPNets []*net.IPNet

				// Per-set slice: appending it to allDetectedCIDRs below
				// copies the values, so its backing array stays owned by
				// the snapshot (never aliased by the emit path).
				var setDetected []output.LiveCIDR

				for _, cidrStr := range cidrs {
					_, ipNet, err := net.ParseCIDR(cidrStr)
					if err != nil {
						logger.Warn("cidr parse error", "cidr", cidrStr, "err", err)
						continue
					}
					cidrIPNets = append(cidrIPNets, ipNet)

					// Use IPNet-native count function for speed
					count := winInst.window.Trie.CountInRangeIPNet(ipNet)
					setDetected = append(setDetected, output.LiveCIDR{
						CIDR:  cidrStr,
						Count: count,
					})
				}
				allDetectedCIDRs = append(allDetectedCIDRs, setDetected...)

				// Only add to jail if useForJail is true
				if useForJail {
					allMergedCIDRs = append(allMergedCIDRs, cidrIPNets...)
				}

				if stats != nil {
					winClusterStats[wi] = append(winClusterStats[wi], newClusterSetStats(argSet, useForJail, clusterDuration, setDetected))
				}

				logger.Debug("cluster set",
					"window", winInst.name,
					"set", i+1,
					"min_size", argSet.MinClusterSize,
					"min_depth", argSet.MinDepth,
					"max_depth", argSet.MaxDepth,
					"threshold", argSet.MeanSubnetDifference,
					"detected", len(setDetected),
					"duration_us", clusterDuration.Microseconds(),
				)
			}
		}

		// Remember this iteration's cluster stats for heartbeat snapshots.
		lastWinClusterStats = winClusterStats

		// Merge all CIDRs collected across configurations
		mergedIPNets := cidr.MergeIPNets(allMergedCIDRs)

		// Convert back to strings for display and jail operations
		var mergedCIDRs []string
		for _, ipNet := range mergedIPNets {
			mergedCIDRs = append(mergedCIDRs, ipNet.String())
		}

		// Whitelists from every source: CIDR list + UA-whitelisted IPs.
		allWhitelists := composeAllWhitelists(whitelistCIDRs, uaWhitelistIPs)

		// Drop fully-whitelisted CIDRs before the jail update without
		// fragmenting partial overlaps (static parity). The whitelist is
		// reapplied exactly at the publish choke point; fragmenting here around
		// UA-whitelisted /32s would explode the jail update super-linearly.
		filteredJailCIDRs, removed := cidr.DropFullyWhitelisted(mergedCIDRs, allWhitelists)
		if len(allWhitelists) > 0 && removed > 0 {
			logger.Warn("whitelist filtering prevented CIDRs from being added to jail", "count", removed)
		}

		// Force-jail IPs seen with blacklisted User-Agents as /32 (static
		// parity). Jail dedups; ban decay handles IPs that stop appearing.
		for ip := range uaBlacklistIPs {
			filteredJailCIDRs = append(filteredJailCIDRs, iputils.Uint32ToIP(ip).String()+"/32")
		}

		if err := jailInstance.Update(filteredJailCIDRs); err != nil {
			logger.Warn("some CIDRs failed during jail update", "err", err)
		}
		// Evict prisoners stale beyond the escalation-memory window before
		// persisting, so jail.json (rewritten in full every iteration) tracks
		// active+recent bans, not lifetime-distinct CIDRs (AUDIT-04).
		prunedJail := jailInstance.Prune(jailInstance.RetentionHorizon())
		if err := jail.JailToFile(jailInstance, cfg.GetJailFile()); err != nil {
			logger.Error("failed to save jail", "path", cfg.GetJailFile(), "err", err)
		}

		// ComposeBanLists is the publish choke point (static parity):
		// whitelists win over active bans AND the manual blacklist.
		activeBans := jailInstance.ListActiveBans()
		publishBans, publishBlacklist := cidr.ComposeBanLists(activeBans, blacklistCIDRs, allWhitelists)
		banContent := jail.BuildBanFileContent(publishBans, publishBlacklist)
		banFileWritten := false
		if err := jail.WriteToFile(cfg.GetBanFile(), banContent); err != nil {
			// On failure statsState keeps the previous content: /bans always
			// serves the last content actually on disk.
			logger.Error("failed to write ban file", "path", cfg.GetBanFile(), "err", err)
		} else {
			banFileWritten = true
			lastBanKey = banListKey(publishBans, publishBlacklist)
			banKeyValid = true
			if statsState != nil {
				statsState.recordBanFileWrite(banContent, len(publishBans)+len(publishBlacklist))
			}
			if len(publishBlacklist) > 0 && !blacklistWarned {
				blacklistWarned = true
				logger.Info("added manual blacklist entries to ban file", "count", len(publishBlacklist))
			}
		}

		loopEnd := time.Since(loopStart)

		// Publish the snapshot before the iteration line so anyone reacting
		// to the log already sees the matching /stats state.
		if stats != nil {
			statsState.uaActiveWhitelistIPs = len(uaWhitelistIPs)
			statsState.uaActiveBlacklistIPs = len(uaBlacklistIPs)
			stats.publish(buildSnapshot(statsState, ing, cfg, windows, winClusterStats, &jailInstance, loopEnd, maxSleepTime, false))
		}

		logger.Info("iteration",
			"window", totalWindowSize,
			"batch", len(batch),
			"detected", len(allDetectedCIDRs),
			"merged", len(mergedCIDRs),
			"jailed", len(filteredJailCIDRs),
			"pruned", prunedJail,
			"active_bans", len(publishBans),
			"ban_file_written", banFileWritten,
			"loop_ms", loopEnd.Milliseconds(),
			"cluster_ms", totalClusterDuration/1000,
		)

		// Sleep using maximum sleep time across all windows
		sleepOrDone(ctx, time.Duration(maxSleepTime)*time.Second)
		lastTick = time.Now()
	}
	return nil
}

// composeAllWhitelists merges the startup whitelist CIDRs with the currently
// tracked UA-whitelisted IPs as /32s. Returns whitelistCIDRs unchanged (zero
// allocation) when no UA IPs are tracked.
func composeAllWhitelists(whitelistCIDRs []string, uaWhitelistIPs map[uint32]time.Time) []string {
	if len(uaWhitelistIPs) == 0 {
		return whitelistCIDRs
	}
	combined := make([]string, 0, len(whitelistCIDRs)+len(uaWhitelistIPs))
	combined = append(combined, whitelistCIDRs...)
	for ip := range uaWhitelistIPs {
		combined = append(combined, iputils.Uint32ToIP(ip).String()+"/32")
	}
	return combined
}

// banListKey is the change-detection key for the published ban lists. The
// NUL separator cannot appear in a CIDR string, so distinct list pairs map
// to distinct keys.
func banListKey(publishBans, publishBlacklist []string) string {
	return strings.Join(publishBans, "\n") + "\x00" + strings.Join(publishBlacklist, "\n")
}

// runHeartbeat keeps live mode honest while no traffic arrives: it expires
// jail bans, persists the jail when bans flipped inactive, rewrites the ban
// file only when the published lists changed, and publishes a heartbeat
// snapshot so /stats keeps advancing. Called from the loop goroutine only.
func runHeartbeat(
	jailInstance *jail.Jail,
	cfg *config.Config,
	logger *slog.Logger,
	stats *statsServer,
	statsState *liveStatsState,
	ing ingestor.Ingestor,
	windows []slidingWindowInstance,
	lastWinClusterStats [][]clusterSetStats,
	whitelistCIDRs []string,
	uaWhitelistIPs map[uint32]time.Time,
	blacklistCIDRs []string,
	lastBanKey *string,
	banKeyValid *bool,
	blacklistWarned *bool,
	maxSleepTime int,
) {
	hbStart := time.Now()

	// Expiry only flips bans active -> inactive, so a count delta is an
	// exact change signal.
	before := len(jailInstance.ListActiveBans())
	jailInstance.UpdateBanActiveStatus()
	after := len(jailInstance.ListActiveBans())
	// Evict prisoners stale beyond the escalation-memory window so jail.json
	// keeps shrinking even during traffic-free periods (AUDIT-04). Pure
	// evictions remove already-inactive prisoners, so they do NOT change the
	// active-ban count; force the save when anything was pruned as well.
	pruned := jailInstance.Prune(jailInstance.RetentionHorizon())
	if after != before || pruned > 0 {
		if err := jail.JailToFile(*jailInstance, cfg.GetJailFile()); err != nil {
			logger.Error("failed to save jail", "path", cfg.GetJailFile(), "err", err)
		}
	}

	// Compose the publish lists exactly like the iteration path. UA-
	// blacklisted IPs are deliberately NOT re-appended as /32 fills: with no
	// traffic those IPs are not recurring, so their bans decay normally.
	allWhitelists := composeAllWhitelists(whitelistCIDRs, uaWhitelistIPs)
	publishBans, publishBlacklist := cidr.ComposeBanLists(jailInstance.ListActiveBans(), blacklistCIDRs, allWhitelists)

	wrote := false
	if key := banListKey(publishBans, publishBlacklist); !*banKeyValid || key != *lastBanKey {
		banContent := jail.BuildBanFileContent(publishBans, publishBlacklist)
		if err := jail.WriteToFile(cfg.GetBanFile(), banContent); err != nil {
			logger.Error("failed to write ban file", "path", cfg.GetBanFile(), "err", err)
		} else {
			wrote = true
			*lastBanKey = key
			*banKeyValid = true
			if statsState != nil {
				statsState.recordBanFileWrite(banContent, len(publishBans)+len(publishBlacklist))
			}
			if len(publishBlacklist) > 0 && !*blacklistWarned {
				*blacklistWarned = true
				logger.Info("added manual blacklist entries to ban file", "count", len(publishBlacklist))
			}
		}
	}

	// Publish before logging so anyone reacting to the heartbeat line
	// already sees the matching /stats state (same order as iterations).
	if stats != nil {
		stats.publish(buildSnapshot(statsState, ing, cfg, windows, lastWinClusterStats, jailInstance, time.Since(hbStart), maxSleepTime, true))
	}

	logger.Debug("heartbeat",
		"expired", before-after,
		"active_bans", len(publishBans),
		"ban_file_written", wrote,
	)
}

// ============================================================================
// OUTPUT FUNCTIONS - Unified output handling (static mode)
// ============================================================================

// outputResult is the unified output function that handles all output formats
func outputResult(jsonOutput *output.JSONOutput, outputConfig OutputConfig) {
	if outputConfig.Plain {
		outputPlain(jsonOutput)
		return
	}

	var jsonBytes []byte
	var err error

	if outputConfig.Compact {
		jsonBytes, err = jsonOutput.ToCompactJSON()
	} else {
		jsonBytes, err = jsonOutput.ToJSON()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal JSON output: %v\n", err)
		return
	}
	fmt.Println(string(jsonBytes))
}

// outputPlain formats the JSON output as human-readable plain text
func outputPlain(jsonOutput *output.JSONOutput) {
	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("                               flokbn Analysis Results\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n\n")

	// General Information
	fmt.Printf("📊 ANALYSIS OVERVIEW\n")
	fmt.Printf("────────────────────────────────────────────────────────────────────────────────\n")
	fmt.Printf("Log File:        %s\n", jsonOutput.General.LogFile)
	fmt.Printf("Analysis Type:   %s\n", jsonOutput.Metadata.AnalysisType)
	fmt.Printf("Generated:       %s\n", jsonOutput.Metadata.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("Duration:        %d ms\n", jsonOutput.Metadata.DurationMS)
	fmt.Printf("\n")

	// Parsing Performance
	fmt.Printf("⚡ PARSING PERFORMANCE\n")
	fmt.Printf("────────────────────────────────────────────────────────────────────────────────\n")
	fmt.Printf("Total Requests:  %s\n", output.FormatNumber(jsonOutput.General.TotalRequests))
	fmt.Printf("Parse Time:      %d ms\n", jsonOutput.General.Parsing.DurationMS)
	fmt.Printf("Parse Rate:      %s requests/sec\n", output.FormatNumber(int(jsonOutput.General.Parsing.RatePerSecond)))
	fmt.Printf("Log Format:      %s\n", jsonOutput.General.Parsing.Format)
	fmt.Printf("\n")

	// Process each trie
	for i, trieResult := range jsonOutput.Tries {
		fmt.Printf("🎯 TRIE: %s\n", trieResult.Name)
		fmt.Printf("────────────────────────────────────────────────────────────────────────────────\n")

		// Trie Statistics
		fmt.Printf("Requests After Filtering: %s\n", output.FormatNumber(trieResult.Stats.TotalRequestsAfterFiltering))
		if trieResult.Stats.UAWhitelistExcluded > 0 {
			fmt.Printf("Excluded (UA whitelist): %s\n", output.FormatNumber(trieResult.Stats.UAWhitelistExcluded))
		}
		fmt.Printf("Unique IPs:              %s\n", output.FormatNumber(trieResult.Stats.UniqueIPs))
		fmt.Printf("Trie Build Time:         %d ms\n", trieResult.Stats.InsertTimeMS)

		// Active Filters
		fmt.Printf("Active Filters:          ")
		filters := output.ActiveFilters(trieResult.Parameters, jsonOutput.GlobalFilters)
		if len(filters) > 0 {
			fmt.Printf("%s\n", strings.Join(filters, ", "))
		} else {
			fmt.Printf("None\n")
		}
		fmt.Printf("\n")

		// CIDR Range Analysis
		if len(trieResult.Stats.CIDRAnalysis) > 0 {
			fmt.Printf("📍 CIDR RANGE ANALYSIS\n")
			fmt.Printf("...............................................................................  \n")
			for _, cidr := range trieResult.Stats.CIDRAnalysis {
				fmt.Printf("  %-20s  %10s requests  (%6.2f%%)\n",
					cidr.CIDR, output.FormatNumber(int(cidr.Requests)), cidr.Percentage)
			}
			fmt.Printf("\n")
		}

		// Clustering Results
		if len(trieResult.Data) > 0 {
			fmt.Printf("🔍 CLUSTERING RESULTS (%d sets)\n", len(trieResult.Data))
			fmt.Printf("...............................................................................  \n")

			for j, cluster := range trieResult.Data {
				fmt.Printf("  Set %d: min_size=%d, depth=%d-%d, threshold=%.2f\n",
					j+1, cluster.Parameters.MinClusterSize, cluster.Parameters.MinDepth,
					cluster.Parameters.MaxDepth, cluster.Parameters.MeanSubnetDifference)
				fmt.Printf("  Execution Time: %d μs\n", cluster.ExecutionTimeUS)

				if len(cluster.MergedRanges) > 0 {
					fmt.Printf("  Detected Threat Ranges:\n")
					var totalThreats uint32
					for _, threat := range cluster.MergedRanges {
						fmt.Printf("    %-20s  %10s requests  (%6.2f%%)\n",
							threat.CIDR, output.FormatNumber(int(threat.Requests)), threat.Percentage)
						totalThreats += threat.Requests
					}
					// Percent-of-requests, matching the per-range percentages
					// computed during clustering (denominator = inserted
					// requests, not unique IPs).
					totalPercentage := float64(totalThreats) / float64(trieResult.Stats.TotalRequestsAfterFiltering) * 100
					fmt.Printf("    %-20s  %10s requests  (%6.2f%%) [TOTAL]\n",
						"───────────────────", output.FormatNumber(int(totalThreats)), totalPercentage)
				} else {
					fmt.Printf("  No significant threat ranges detected\n")
				}
				fmt.Printf("\n")
			}
		}

		// Add separator between tries
		if i < len(jsonOutput.Tries)-1 {
			fmt.Printf("===============================================================================\n\n")
		}
	}

	// Warnings and Errors
	if len(jsonOutput.Warnings) > 0 || len(jsonOutput.Errors) > 0 {
		fmt.Printf("⚠️  DIAGNOSTICS\n")
		fmt.Printf("────────────────────────────────────────────────────────────────────────────────\n")

		if len(jsonOutput.Warnings) > 0 {
			fmt.Printf("Warnings:\n")
			for _, warning := range jsonOutput.Warnings {
				if warning.Type != "info" { // Skip info messages in plain output
					fmt.Printf("  • %s\n", warning.Message)
				}
			}
		}

		if len(jsonOutput.Errors) > 0 {
			fmt.Printf("Errors:\n")
			for _, err := range jsonOutput.Errors {
				fmt.Printf("  • %s\n", err.Message)
			}
		}

		fmt.Printf("\n")
	}

	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
}

// Active-filter rendering lives in output.ActiveFilters, shared with the TUI so
// the two renderers never drift (and so the global whitelists are always
// listed, not just the per-trie TrieParameters).
