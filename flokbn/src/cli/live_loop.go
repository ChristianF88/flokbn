package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/iputils"
	"github.com/ChristianF88/flokbn/jail"
	"github.com/ChristianF88/flokbn/output"
	"github.com/ChristianF88/flokbn/sliding"
)

// slidingWindowInstance holds a sliding window and its associated configuration
type slidingWindowInstance struct {
	name   string
	window *sliding.SlidingWindow
	config *config.SlidingTrieConfig

	// Lifetime counters, owned by the loop goroutine (no atomics needed).
	acceptedTotal uint64
	rejectedTotal uint64 // ShouldIncludeRequest rejections; zero-ts/IP skips excluded
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
	// liveTimestampSkewInterval rate-limits the per-window warning about
	// request timestamps that disagree with the wall clock.
	liveTimestampSkewInterval = time.Minute
	// liveTimestampSkewMsg is that warning's message.
	liveTimestampSkewMsg = "most request timestamps fall outside the sliding window on arrival"
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
		return fmt.Errorf("at least one sliding window is required in live mode (e.g. [live.<name>])")
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

	// Accept only starts serving the listener; it does not wait for a client.
	// Real connects and disconnects are logged by the ingestor ("Filebeat
	// connected" / "Filebeat disconnected") and counted in its stats.
	if err := ing.Accept(); err != nil {
		return fmt.Errorf("accepting connection: %w", err)
	}

	logger.Info("waiting for Filebeat to connect")

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
	// and publish snapshots - otherwise bans never lift (lockout feedback
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
	// Change detection for jail.json, shared by iterations and heartbeats.
	var jailSave jailFileState
	// Last iteration's per-window cluster stats, re-served by heartbeat
	// snapshots (no traffic means no new clustering result).
	var lastWinClusterStats [][]clusterSetStats
	// Per-window time of the last timestamp-skew warning (rate limit).
	lastSkewWarn := make([]time.Time, len(windows))

	for {
		loopStart := time.Now()

		batch, err := ing.ReadBatch()
		if err != nil {
			return fmt.Errorf("reading batch: %w", err)
		}

		if len(batch) == 0 && ing.IsClosed() {
			// A batch can be queued between the empty read above and the
			// close. Read once more now that nothing can be added, so the
			// last batch before shutdown is processed instead of dropped.
			batch, err = ing.ReadBatch()
			if err != nil {
				return fmt.Errorf("reading batch: %w", err)
			}
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
					maxSleepTime, &jailSave)
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

			// Time-based expiry compares log time with the wall clock. When
			// most of a batch is already outside the window on arrival the
			// two disagree: stale requests expire before clustering sees
			// them (nothing is ever detected), future-stamped ones are
			// clamped to their arrival time. Say so instead of staying
			// silent; the usual cause is a zone-less log format on a host
			// that is not on UTC.
			if arr := winInst.window.LastArrival(); (arr.Stale+arr.Future)*2 > arr.Inserted &&
				loopStart.Sub(lastSkewWarn[wi]) >= liveTimestampSkewInterval {
				lastSkewWarn[wi] = loopStart
				logger.Warn(liveTimestampSkewMsg,
					"window", winInst.name,
					"batch", arr.Inserted,
					"stale", arr.Stale,
					"future", arr.Future,
					"window_max_time", winInst.config.SlidingWindowMaxTime.String(),
					"hint", "timestamps without a UTC offset are read as UTC; log the offset or check the clock on the log host",
				)
			}

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
		// persisting, so jail.json (written in full whenever it changes) tracks
		// active+recent bans, not lifetime-distinct CIDRs (AUDIT-04).
		prunedJail := jailInstance.Prune(jailInstance.RetentionHorizon())
		// Persist only when the serialized jail changed (or the file is gone):
		// most iterations re-detect ranges that are already banned.
		jailFileWritten, saveErr := jailSave.save(&jailInstance, cfg.GetJailFile())
		if saveErr != nil {
			logger.Error("failed to save jail", "path", cfg.GetJailFile(), "err", saveErr)
		}

		// ComposeBanLists is the publish choke point (static parity):
		// whitelists win over active bans AND the manual blacklist.
		activeBans := jailInstance.ListActiveBans()
		publishBans, publishBlacklist := cidr.ComposeBanLists(activeBans, blacklistCIDRs, allWhitelists)
		banFileWritten := false
		// Same change detection as the heartbeat: the ban file (and its
		// timestamp header) is rewritten only when the published lists
		// changed, when no write has succeeded yet, or when the file is gone.
		if banKey := banListKey(publishBans, publishBlacklist); !banKeyValid || banKey != lastBanKey || fileMissing(cfg.GetBanFile()) {
			banContent := jail.BuildBanFileContent(publishBans, publishBlacklist)
			if err := jail.WriteToFile(cfg.GetBanFile(), banContent); err != nil {
				// On failure statsState keeps the previous content: /bans always
				// serves the last content actually on disk.
				logger.Error("failed to write ban file", "path", cfg.GetBanFile(), "err", err)
			} else {
				banFileWritten = true
				lastBanKey = banKey
				banKeyValid = true
				if statsState != nil {
					statsState.recordBanFileWrite(banContent, len(publishBans)+len(publishBlacklist))
				}
				if len(publishBlacklist) > 0 && !blacklistWarned {
					blacklistWarned = true
					logger.Info("added manual blacklist entries to ban file", "count", len(publishBlacklist))
				}
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
			"jail_file_written", jailFileWritten,
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
// the sliding windows (refreshing the published detections), expires jail
// bans, persists the jail when bans flipped inactive, rewrites the ban
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
	jailSave *jailFileState,
) {
	hbStart := time.Now()

	// Expire the sliding windows. Update only runs when a batch arrives, so
	// without this an idle loop would keep serving the window size, unique
	// IPs, detections and top talkers of the last busy moment (and hold the
	// memory). When entries left a window its published clustering result and
	// top talkers are recomputed for the stats view only; the jail is not
	// involved, bans are still raised by the iteration path alone.
	windowExpired := 0
	for i := range windows {
		w := &windows[i]
		queued := len(w.window.IPQueue)
		w.window.DropOld()
		evicted := queued - len(w.window.IPQueue)
		if evicted == 0 {
			continue
		}
		windowExpired += evicted
		if lastWinClusterStats != nil {
			// Replaces one element of the loop-owned outer slice; published
			// snapshots only hold the inner slices, which stay untouched.
			lastWinClusterStats[i] = clusterStatsForWindow(w)
		}
		if statsState != nil {
			statsState.refreshTopTalkers(cfg, windows, i)
		}
	}

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
		// Through jailSave so the iteration path's change detection knows
		// what is on disk.
		if _, err := jailSave.save(jailInstance, cfg.GetJailFile()); err != nil {
			logger.Error("failed to save jail", "path", cfg.GetJailFile(), "err", err)
		}
	}

	// Compose the publish lists exactly like the iteration path. UA-
	// blacklisted IPs are deliberately NOT re-appended as /32 fills: with no
	// traffic those IPs are not recurring, so their bans decay normally.
	allWhitelists := composeAllWhitelists(whitelistCIDRs, uaWhitelistIPs)
	publishBans, publishBlacklist := cidr.ComposeBanLists(jailInstance.ListActiveBans(), blacklistCIDRs, allWhitelists)

	wrote := false
	if key := banListKey(publishBans, publishBlacklist); !*banKeyValid || key != *lastBanKey || fileMissing(cfg.GetBanFile()) {
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
		"window_expired", windowExpired,
	)
}
