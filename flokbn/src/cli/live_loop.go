package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/analysis"
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

	// lastSkewWarn is when the timestamp-skew warning was last logged for
	// this window (rate limit).
	lastSkewWarn time.Time
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
	// heartbeat normally fires every sleepS seconds, but configs with
	// SleepBetweenIterations 0 (tests, aggressive setups) still need bans to
	// expire and snapshots to advance during zero-traffic stretches.
	liveHeartbeatFloor = time.Second
	// liveIdlePoll is how long the loop sleeps after an empty ReadBatch
	// before polling again (ReadBatch is non-blocking).
	liveIdlePoll = time.Second
	// liveAcceptingMsg is logged once the ingestor serves its listener. The
	// loop does not wait for a client after it: connects are logged by the
	// ingestor when they happen.
	liveAcceptingMsg = "accepting Lumberjack connections"
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

// liveLoop is one run of live mode: the sliding windows, the lists, the jail
// and everything the loop remembers between rounds. A round is either an
// iteration (a batch arrived) or a heartbeat (the loop is idle). All fields
// are owned by the goroutine that calls run.
type liveLoop struct {
	cfg    *config.Config
	logger *slog.Logger
	ing    ingestor.Ingestor

	// stats is nil when the stats server is off, and statsState with it: no
	// snapshot is built then.
	stats      *statsServer
	statsState *liveStatsState

	windows []slidingWindowInstance
	// sleepS (seconds to pause after an iteration) and maxWindowTime are the
	// largest values across the windows.
	sleepS        int
	maxWindowTime time.Duration
	// heartbeatInterval is how long the loop may stay idle before it runs a
	// heartbeat, measured from lastTick, the end of the last round.
	heartbeatInterval time.Duration
	lastTick          time.Time

	// The CIDR list files, loaded once at startup.
	whitelist []string
	blacklist []string
	// uaMatcher classifies User-Agents against the global lists; nil when
	// neither list is configured.
	uaMatcher *cidr.UserAgentMatcher
	// IPs seen with listed User-Agents, with last-seen times. Purged after
	// the largest window duration each round, so memory stays bounded by
	// the unique listed IPs per window.
	uaWhitelistIPs map[uint32]time.Time
	uaBlacklistIPs map[uint32]time.Time

	jail jail.Jail
	// Change detection for jail.json and the ban file, shared by iterations
	// and heartbeats.
	jailFile jailFileState
	banFile  banFileState
	// blacklistAnnounced: the "added manual blacklist entries" line is logged
	// once per run, on the first ban-file write that carries any.
	blacklistAnnounced bool

	// clusterStats is the last iteration's per-window cluster stats,
	// re-served by heartbeat snapshots (no traffic means no new clustering
	// result). Nil when stats are off and before the first iteration.
	clusterStats [][]clusterSetStats
}

// runLiveLoop is the context-cancellable core of live mode. logger receives
// leveled progress/diagnostic lines (production: the process-wide slog logger
// on stderr); machine-readable data is served by the stats server endpoints.
// Cancelling ctx closes the ingestor, which makes the loop exit cleanly.
// stats is optional: when non-nil the loop publishes an immutable snapshot
// to it after each full iteration (nil = feature off, zero extra work).
func runLiveLoop(ctx context.Context, ing ingestor.Ingestor, cfg *config.Config, logger *slog.Logger, stats *statsServer) error {
	l, err := newLiveLoop(ing, cfg, logger, stats)
	if err != nil {
		return err
	}
	return l.run(ctx)
}

// newLiveLoop builds the windows and loads the lists and the jail. Nothing is
// served yet: a broken list or jail file fails here, before run starts the
// ingestor.
func newLiveLoop(ing ingestor.Ingestor, cfg *config.Config, logger *slog.Logger, stats *statsServer) (*liveLoop, error) {
	if len(cfg.LiveTries) == 0 {
		return nil, fmt.Errorf("at least one sliding window is required in live mode (e.g. [live.<name>])")
	}
	l := &liveLoop{cfg: cfg, logger: logger, ing: ing, stats: stats}

	// One sliding window per LiveTries entry.
	for name, slidingConfig := range cfg.LiveTries {
		l.windows = append(l.windows, slidingWindowInstance{
			name: name,
			window: sliding.NewSlidingWindowTrie(
				slidingConfig.SlidingWindowMaxTime,
				slidingConfig.SlidingWindowMaxSize,
			),
			config: slidingConfig,
		})
		if slidingConfig.SleepBetweenIterations > l.sleepS {
			l.sleepS = slidingConfig.SleepBetweenIterations
		}
		if slidingConfig.SlidingWindowMaxTime > l.maxWindowTime {
			l.maxWindowTime = slidingConfig.SlidingWindowMaxTime
		}
	}

	// Idle heartbeat. ReadBatch is non-blocking, so during zero-traffic
	// stretches the loop must still expire jail bans, refresh the ban file,
	// and publish snapshots - otherwise bans never lift (lockout feedback
	// loop) and /stats freezes.
	l.heartbeatInterval = time.Duration(l.sleepS) * time.Second
	if l.heartbeatInterval < liveHeartbeatFloor {
		l.heartbeatInterval = liveHeartbeatFloor
	}

	// Load whitelist/blacklist once at startup. A broken list config fails
	// loud instead of silently banning whitelisted ranges.
	var err error
	if l.whitelist, err = cfg.LoadWhitelistCIDRs(); err != nil {
		return nil, fmt.Errorf("loading whitelist: %w", err)
	}
	if l.blacklist, err = cfg.LoadBlacklistCIDRs(); err != nil {
		return nil, fmt.Errorf("loading blacklist: %w", err)
	}

	// User-Agent lists (static parity): exact case-insensitive matching via
	// the same matcher static mode uses. Broken list files fail loud at
	// startup, like the CIDR lists above.
	uaWhitelistPatterns, err := cfg.LoadUserAgentWhitelistPatterns()
	if err != nil {
		return nil, fmt.Errorf("loading user-agent whitelist: %w", err)
	}
	uaBlacklistPatterns, err := cfg.LoadUserAgentBlacklistPatterns()
	if err != nil {
		return nil, fmt.Errorf("loading user-agent blacklist: %w", err)
	}
	if len(uaWhitelistPatterns) > 0 || len(uaBlacklistPatterns) > 0 {
		l.uaMatcher = cidr.NewUserAgentMatcher(uaWhitelistPatterns, uaBlacklistPatterns)
		logger.Info("user-agent lists loaded",
			"whitelist_patterns", len(uaWhitelistPatterns),
			"blacklist_patterns", len(uaBlacklistPatterns),
		)
	}
	l.uaWhitelistIPs = make(map[uint32]time.Time)
	l.uaBlacklistIPs = make(map[uint32]time.Time)

	if l.jail, err = jail.FileToJail(cfg.GetJailFile()); err != nil {
		return nil, fmt.Errorf("reading jail file: %w", err)
	}

	if stats != nil {
		l.statsState = newLiveStatsState(cfg, l.whitelist, l.blacklist)
	}
	return l, nil
}

// run serves the ingestor and processes batches until the ingestor is closed,
// which cancelling ctx brings about.
func (l *liveLoop) run(ctx context.Context) error {
	// Accept only starts serving the listener; it does not wait for a client.
	// Real connects and disconnects are logged by the ingestor ("Filebeat
	// connected" / "Filebeat disconnected") and counted in its stats.
	if err := l.ing.Accept(); err != nil {
		return fmt.Errorf("accepting connection: %w", err)
	}

	l.logger.Info(liveAcceptingMsg)

	// Cancellation watcher: closing the ingestor unblocks the loop below.
	// Started only after Accept so ing's internal state is never written
	// concurrently with Close.
	loopDone := make(chan struct{})
	defer close(loopDone)
	go func() {
		select {
		case <-ctx.Done():
			l.ing.Close()
		case <-loopDone:
		}
	}()

	l.lastTick = time.Now()
	for {
		loopStart := time.Now()

		batch, err := l.readBatch()
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			if l.ing.IsClosed() {
				l.logger.Info("ingestor closed, exiting loop")
				return nil
			}
			l.idle(ctx)
			continue
		}

		l.iterate(ctx, batch, loopStart)

		// Sleep using maximum sleep time across all windows
		sleepOrDone(ctx, time.Duration(l.sleepS)*time.Second)
		l.lastTick = time.Now()
	}
}

// readBatch returns everything the ingestor has queued, without blocking;
// an empty batch means nothing arrived.
func (l *liveLoop) readBatch() ([]accesslog.Request, error) {
	batch, err := l.ing.ReadBatch()
	if err != nil {
		return nil, fmt.Errorf("reading batch: %w", err)
	}
	if len(batch) == 0 && l.ing.IsClosed() {
		// A batch can be queued between the empty read above and the
		// close. Read once more now that nothing can be added, so the
		// last batch before shutdown is processed instead of dropped.
		batch, err = l.ing.ReadBatch()
		if err != nil {
			return nil, fmt.Errorf("reading batch: %w", err)
		}
	}
	return batch, nil
}

// idle waits for the next poll and runs a heartbeat when one is due.
func (l *liveLoop) idle(ctx context.Context) {
	sleepOrDone(ctx, liveIdlePoll)
	if time.Since(l.lastTick) < l.heartbeatInterval {
		return
	}
	// Window-aligned expiry must run on the idle path too, before the
	// heartbeat composes whitelists: otherwise a stale UA-whitelisted /32
	// keeps suppressing an active jail ban for the whole idle stretch (it
	// never re-appears until traffic resumes).
	if l.uaMatcher != nil {
		l.purgeUserAgentIPs(time.Now())
	}
	l.heartbeat()
	l.lastTick = time.Now()
}

// classifyUserAgents checks every request of the batch against the global
// User-Agent lists (they are global, not per-window) and returns the batch
// without the whitelisted-UA requests, filtered in place. Those never enter
// any window (parity with static trie exclusion) and immunize their IP at
// publish time; blacklisted-UA IPs are force-jailed as /32 by the iteration.
func (l *liveLoop) classifyUserAgents(batch []accesslog.Request) []accesslog.Request {
	now := time.Now()
	kept := batch[:0]
	for _, msg := range batch {
		switch l.uaMatcher.CheckUserAgent(msg.UserAgent) {
		case cidr.UserAgentWhitelist:
			if msg.IPUint32 != 0 {
				l.uaWhitelistIPs[msg.IPUint32] = now
			}
			if l.statsState != nil {
				l.statsState.uaWhitelistHits++
			}
			continue
		case cidr.UserAgentBlacklist:
			if msg.IPUint32 != 0 {
				l.uaBlacklistIPs[msg.IPUint32] = now
			}
			if l.statsState != nil {
				l.statsState.uaBlacklistHits++
			}
		}
		kept = append(kept, msg)
	}
	l.purgeUserAgentIPs(now)
	return kept
}

// purgeUserAgentIPs forgets listed-UA IPs not seen for the largest window
// duration (window-aligned expiry keeps both sets bounded).
func (l *liveLoop) purgeUserAgentIPs(now time.Time) {
	cutoff := now.Add(-l.maxWindowTime)
	purgeExpired(l.uaWhitelistIPs, cutoff)
	purgeExpired(l.uaBlacklistIPs, cutoff)
}

// feedWindow puts the requests of the batch that pass the window's filters
// into the window, which also expires what has left it.
func (l *liveLoop) feedWindow(w *slidingWindowInstance, batch []accesslog.Request) {
	timedIps := make([]sliding.TimedIP, 0, len(batch))
	for _, msg := range batch {
		if msg.Timestamp.IsZero() || msg.IPUint32 == 0 {
			continue
		}

		// Apply regex filtering based on window config
		if !w.config.ShouldIncludeRequest(msg) {
			w.rejectedTotal++
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
	w.acceptedTotal += uint64(len(timedIps))

	w.window.Update(timedIps)
}

// warnTimestampSkew says so when most of the batch just fed to the window
// was already outside it on arrival. Time-based expiry compares log time
// with the wall clock; when the two disagree, stale requests expire before
// clustering sees them (nothing is ever detected) and future-stamped ones
// are clamped to their arrival time. The usual cause is a zone-less log
// format on a host that is not on UTC.
func (l *liveLoop) warnTimestampSkew(w *slidingWindowInstance, now time.Time) {
	arr := w.window.LastArrival()
	if (arr.Stale+arr.Future)*2 <= arr.Inserted || now.Sub(w.lastSkewWarn) < liveTimestampSkewInterval {
		return
	}
	w.lastSkewWarn = now
	l.logger.Warn(liveTimestampSkewMsg,
		"window", w.name,
		"batch", arr.Inserted,
		"stale", arr.Stale,
		"future", arr.Future,
		"window_max_time", w.config.SlidingWindowMaxTime.String(),
		"hint", "timestamps without a UTC offset are read as UTC; log the offset or check the clock on the log host",
	)
}

// clusterSetResult is what one cluster arg set found in one window.
type clusterSetResult struct {
	argSet     config.ClusterArgSet
	useForJail bool
	duration   time.Duration
	// detected holds the ranges with their request counts, nets the same
	// ranges parsed, index for index. Both are freshly allocated: detected
	// goes into a published snapshot, which owns it from then on.
	detected []output.LiveCIDR
	nets     []*net.IPNet
}

// clusterWindow runs every cluster arg set on the window as it is now. It is
// the one place live mode clusters. An iteration hands the ranges of the
// sets flagged useForJail to the jail; a heartbeat, after it expired entries
// from the window, only republishes the result for the stats view.
func (l *liveLoop) clusterWindow(w *slidingWindowInstance) []clusterSetResult {
	results := make([]clusterSetResult, len(w.config.ClusterArgSets))
	for i, argSet := range w.config.ClusterArgSets {
		r := &results[i]
		r.argSet = argSet
		r.useForJail = i < len(w.config.UseForJail) && w.config.UseForJail[i]

		start := time.Now()
		cidrs := w.window.Trie.CollectCIDRs(
			argSet.MinClusterSize,
			argSet.MinDepth,
			argSet.MaxDepth,
			argSet.MeanSubnetDifference,
		)
		r.duration = time.Since(start)
		if len(cidrs) == 0 {
			continue
		}

		// Parse each range once: the net serves the count here and the
		// merge before the jail.
		r.detected = make([]output.LiveCIDR, 0, len(cidrs))
		r.nets = make([]*net.IPNet, 0, len(cidrs))
		for _, cidrStr := range cidrs {
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				l.logger.Warn("cidr parse error", "cidr", cidrStr, "err", err)
				continue
			}
			r.nets = append(r.nets, ipNet)
			r.detected = append(r.detected, output.LiveCIDR{
				CIDR: cidrStr,
				// Use IPNet-native count function for speed
				Count: w.window.Trie.CountInRangeIPNet(ipNet),
			})
		}
	}
	return results
}

// windowsRound is what one iteration found across all windows.
type windowsRound struct {
	jailNets  []*net.IPNet // ranges detected by the cluster sets flagged useForJail
	detected  int          // ranges detected by any cluster set
	requests  int          // requests held by the windows after the update
	clusterUS int64        // time spent clustering, in microseconds
}

// updateWindows feeds the batch to every window and clusters each of them.
// With stats on it also records the per-set results for the snapshot (and
// for the heartbeat snapshots that follow).
func (l *liveLoop) updateWindows(batch []accesslog.Request, now time.Time) windowsRound {
	var round windowsRound
	var winClusterStats [][]clusterSetStats
	if l.stats != nil {
		winClusterStats = make([][]clusterSetStats, len(l.windows))
	}

	// By pointer: the lifetime counters persist.
	for wi := range l.windows {
		w := &l.windows[wi]
		l.feedWindow(w, batch)
		round.requests += len(w.window.IPQueue)
		l.warnTimestampSkew(w, now)

		results := l.clusterWindow(w)
		for i := range results {
			r := &results[i]
			round.clusterUS += r.duration.Microseconds()
			round.detected += len(r.detected)
			if r.useForJail {
				round.jailNets = append(round.jailNets, r.nets...)
			}
			l.logger.Debug("cluster set",
				"window", w.name,
				"set", i+1,
				"min_size", r.argSet.MinClusterSize,
				"min_depth", r.argSet.MinDepth,
				"max_depth", r.argSet.MaxDepth,
				"threshold", r.argSet.MeanSubnetDifference,
				"detected", len(r.detected),
				"duration_us", r.duration.Microseconds(),
			)
		}
		if l.stats != nil {
			winClusterStats[wi] = clusterStatsOf(results)
		}
	}
	l.clusterStats = winClusterStats
	return round
}

// iterate processes one batch: it feeds and clusters every window, hands the
// detected ranges to the jail, writes the files that changed and publishes
// the snapshot.
func (l *liveLoop) iterate(ctx context.Context, batch []accesslog.Request, loopStart time.Time) {
	if l.logger.Enabled(ctx, slog.LevelDebug) {
		ingSt := l.ing.Stats()
		l.logger.Debug("batch read",
			"size", len(batch),
			"queue_depth", ingSt.QueueDepth,
			"parse_errors_total", ingSt.ParseErrorsTotal,
			"malformed_fields_total", ingSt.MalformedFieldsTotal,
		)
	}

	if l.uaMatcher != nil {
		batch = l.classifyUserAgents(batch)
	}

	windows := l.updateWindows(batch, loopStart)

	// Merge the ranges collected across windows and cluster sets, then back
	// to strings for the jail.
	var mergedCIDRs []string
	for _, ipNet := range cidr.MergeIPNets(windows.jailNets) {
		mergedCIDRs = append(mergedCIDRs, ipNet.String())
	}

	bans := l.publishBans(mergedCIDRs, l.forcedBans(), false)

	loopEnd := time.Since(loopStart)

	// Publish the snapshot before the iteration line so anyone reacting
	// to the log already sees the matching /stats state.
	if l.stats != nil {
		l.statsState.uaActiveWhitelistIPs = len(l.uaWhitelistIPs)
		l.statsState.uaActiveBlacklistIPs = len(l.uaBlacklistIPs)
		l.publishSnapshot(loopEnd, false)
	}

	l.logger.Info("iteration",
		"window", windows.requests,
		"batch", len(batch),
		"detected", windows.detected,
		"merged", len(mergedCIDRs),
		"jailed", bans.Jailed,
		"pruned", bans.pruned,
		"active_bans", len(bans.Bans),
		"ban_file_written", bans.banFileWritten,
		"jail_file_written", bans.jailFileWritten,
		"loop_ms", loopEnd.Milliseconds(),
		"cluster_ms", windows.clusterUS/1000,
	)
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

// forcedBans lists the IPs seen with a blacklisted User-Agent as /32 ranges.
// An iteration hands them to the jail whatever the batch held (static
// parity). The jail dedups; ban decay handles IPs that stop appearing.
func (l *liveLoop) forcedBans() []string {
	if len(l.uaBlacklistIPs) == 0 {
		return nil
	}
	forced := make([]string, 0, len(l.uaBlacklistIPs))
	for ip := range l.uaBlacklistIPs {
		forced = append(forced, iputils.Uint32ToIP(ip).String()+"/32")
	}
	return forced
}

// banRound is the outcome of one round of the ban pipeline in live mode.
type banRound struct {
	analysis.BanUpdate
	pruned          int // prisoners evicted from the jail
	jailFileWritten bool
	banFileWritten  bool
}

// publishBans runs one round of the ban pipeline and writes what changed. It
// is the only place live mode touches the jail and the ban file:
//
//   - analysis.UpdateBans, shared with static mode, drops the detected ranges
//     that are fully whitelisted (without fragmenting partial overlaps),
//     expires the bans that ran out, starts or escalates a ban for every
//     range handed in, and composes the lists to publish, where the
//     whitelist wins over the active bans AND the manual blacklist;
//   - prisoners stale beyond the escalation-memory window are evicted, so
//     jail.json tracks active+recent bans, not lifetime-distinct CIDRs
//     (AUDIT-04);
//   - jail.json and the ban file are written when their content changed.
//
// An iteration hands in the merged ranges it detected and the forced bans. A
// heartbeat hands in nothing, so it only expires: without traffic no ban is
// ever started or escalated, and the IPs of blacklisted User-Agents are not
// re-jailed, so their bans decay normally.
func (l *liveLoop) publishBans(detected, forceBan []string, heartbeat bool) banRound {
	round := banRound{BanUpdate: analysis.UpdateBans(&l.jail, analysis.BanInput{
		Detected: detected,
		ForceBan: forceBan,
		// Whitelists from every source: CIDR list + UA-whitelisted IPs.
		Whitelist: composeAllWhitelists(l.whitelist, l.uaWhitelistIPs),
		Blacklist: l.blacklist,
	})}
	if round.WhitelistDropped > 0 {
		l.logger.Warn("whitelist filtering prevented CIDRs from being added to jail", "count", round.WhitelistDropped)
	}
	if round.UpdateErr != nil {
		l.logger.Warn("some CIDRs failed during jail update", "err", round.UpdateErr)
	}

	// Pure evictions remove already-inactive prisoners, so they change
	// neither the active bans nor the lists composed above.
	round.pruned = l.jail.Prune(l.jail.RetentionHorizon())

	// An iteration compares the serialized jail with the last write every
	// time: most iterations re-detect ranges that are already banned, and a
	// jail file that went missing comes back. A heartbeat skips even the
	// comparison unless a ban ran out or a prisoner was evicted.
	if !heartbeat || round.JailChanged || round.pruned > 0 {
		round.jailFileWritten = l.saveJail()
	}
	round.banFileWritten = l.writeBanFile(round.Bans, round.Blacklist)
	return round
}

// saveJail persists the jail when its serialized form differs from the last
// write or the file is gone, and reports whether it wrote. Iterations and
// heartbeats both save through here, so each knows what the other put on
// disk.
func (l *liveLoop) saveJail() bool {
	path := l.cfg.GetJailFile()
	wrote, err := l.jailFile.save(&l.jail, path)
	if err != nil {
		l.logger.Error("failed to save jail", "path", path, "err", err)
	}
	return wrote
}

// writeBanFile writes the published lists to the ban file and reports whether
// it did. The file (and its timestamp header) is rewritten only when the
// lists changed, when no write has succeeded yet, or when the file is gone.
func (l *liveLoop) writeBanFile(bans, blacklist []string) bool {
	path := l.cfg.GetBanFile()
	content, wrote, err := l.banFile.save(bans, blacklist, path)
	if err != nil {
		// On failure statsState keeps the previous content: /bans always
		// serves the last content actually on disk.
		l.logger.Error("failed to write ban file", "path", path, "err", err)
		return false
	}
	if !wrote {
		return false
	}
	if l.statsState != nil {
		l.statsState.recordBanFileWrite(content, len(bans)+len(blacklist))
	}
	if len(blacklist) > 0 && !l.blacklistAnnounced {
		l.blacklistAnnounced = true
		l.logger.Info("added manual blacklist entries to ban file", "count", len(blacklist))
	}
	return true
}

// publishSnapshot hands the stats server a fresh snapshot; a no-op when the
// stats server is off.
func (l *liveLoop) publishSnapshot(duration time.Duration, heartbeat bool) {
	if l.stats == nil {
		return
	}
	l.stats.publish(buildSnapshot(l.statsState, l.ing, l.cfg, l.windows, l.clusterStats, &l.jail, duration, l.sleepS, heartbeat))
}

// expireWindows drops what has left the sliding windows and returns how many
// entries went. Update only runs when a batch arrives, so without this an
// idle loop would keep serving the window size, unique IPs, detections and
// top talkers of the last busy moment (and hold the memory). When entries
// left a window its published clustering result and top talkers are
// recomputed for the stats view only; the jail is not involved, bans are
// still raised by the iteration path alone.
func (l *liveLoop) expireWindows() int {
	expired := 0
	for i := range l.windows {
		w := &l.windows[i]
		queued := len(w.window.IPQueue)
		w.window.DropOld()
		evicted := queued - len(w.window.IPQueue)
		if evicted == 0 {
			continue
		}
		expired += evicted
		if l.clusterStats != nil {
			// Replaces one element of the loop-owned outer slice; published
			// snapshots only hold the inner slices, which stay untouched.
			l.clusterStats[i] = clusterStatsOf(l.clusterWindow(w))
		}
		if l.statsState != nil {
			l.statsState.refreshTopTalkers(l.cfg, l.windows, i)
		}
	}
	return expired
}

// heartbeat keeps live mode honest while no traffic arrives: it expires
// the sliding windows (refreshing the published detections), expires jail
// bans, persists the jail when bans flipped inactive, rewrites the ban
// file only when the published lists changed, and publishes a heartbeat
// snapshot so /stats keeps advancing.
func (l *liveLoop) heartbeat() {
	hbStart := time.Now()

	windowExpired := l.expireWindows()

	bans := l.publishBans(nil, nil, true)

	// Publish before logging so anyone reacting to the heartbeat line
	// already sees the matching /stats state (same order as iterations).
	l.publishSnapshot(time.Since(hbStart), true)

	l.logger.Debug("heartbeat",
		"expired", bans.Expired,
		"active_bans", len(bans.Bans),
		"ban_file_written", bans.banFileWritten,
		"window_expired", windowExpired,
	)
}
