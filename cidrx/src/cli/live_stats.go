package cli

import (
	"fmt"
	"time"

	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/jail"
	"github.com/ChristianF88/cidrx/output"
	"github.com/ChristianF88/cidrx/sliding"
)

const (
	// statsSchemaVersion identifies the /stats JSON layout; bump on breaking
	// changes so consumers can detect them.
	statsSchemaVersion = 1
	// maxActiveBansInSnapshot caps jail.active_bans; total_active stays exact.
	maxActiveBansInSnapshot = 500
	// maxListCIDRsInSnapshot caps lists.*.cidrs; entries stays exact.
	maxListCIDRsInSnapshot = 1000
	// topTalkersInterval recomputes top talkers every Kth iteration; cached
	// in between. Iteration 1 computes (deterministic for tests).
	topTalkersInterval = 5
)

// statsSnapshot is the immutable per-iteration view served by /stats and
// /bans. The loop builds a fresh one each iteration and publishes it via
// atomic.Pointer; handlers must never mutate it.
type statsSnapshot struct {
	SchemaVersion int           `json:"schema_version"`
	GeneratedAt   time.Time     `json:"generated_at"`
	UptimeS       int64         `json:"uptime_s"`
	Ingest        ingestStats   `json:"ingest"`
	Windows       []windowStats `json:"windows"`
	Jail          jailStats     `json:"jail"`
	Lists         listsStats    `json:"lists"`
	Loop          loopStats     `json:"loop"`

	banFileContent string // served verbatim by /bans; immutable
}

type ingestStats struct {
	Connected            bool      `json:"connected"`
	QueueDepth           int       `json:"queue_depth"`
	LastBatchAt          time.Time `json:"last_batch_at"`
	BatchesTotal         uint64    `json:"batches_total"`
	RequestsTotal        uint64    `json:"requests_total"`
	ParseErrorsTotal     uint64    `json:"parse_errors_total"`
	MalformedFieldsTotal uint64    `json:"malformed_fields_total"`
}

type windowStats struct {
	Name                  string              `json:"name"`
	SizeIPs               int                 `json:"size_ips"` // unique IPs
	Requests              int                 `json:"requests"` // queue length, matches stdout window_size semantics
	AcceptedTotal         uint64              `json:"accepted_total"`
	RejectedByFilterTotal uint64              `json:"rejected_by_filter_total"`
	ClusterSets           []clusterSetStats   `json:"cluster_sets"`
	TopTalkers            []sliding.TopTalker `json:"top_talkers,omitempty"` // gated by [live] topTalkers
}

type clusterParams struct {
	MinSize   uint32  `json:"min_size"`
	Depth     string  `json:"depth"` // "minDepth-maxDepth"
	Threshold float64 `json:"threshold"`
}

type clusterSetStats struct {
	Params         clusterParams `json:"params"`
	UseForJail     bool          `json:"use_for_jail"`
	LastDurationUS int64         `json:"last_duration_us"`
	// DetectedNow is the latest clustering result. Heartbeat snapshots
	// (idle loop, no new traffic) carry the last iteration's result.
	DetectedNow []output.LiveCIDR `json:"detected_now"`
}

type jailStage struct {
	Stage       int    `json:"stage"`
	BanDuration string `json:"ban_duration"`
	Active      int    `json:"active"`
}

type activeBanJSON struct {
	CIDR      string    `json:"cidr"`
	Stage     int       `json:"stage"`
	BanStart  time.Time `json:"ban_start"`
	ExpiresAt time.Time `json:"expires_at"`
}

// jailStats reflects JAIL TRUTH (pre-whitelist); the whitelist-filtered view
// is what lists.ban_file and /bans expose.
type jailStats struct {
	TotalActive int             `json:"total_active"`
	Stages      []jailStage     `json:"stages"`
	ActiveBans  []activeBanJSON `json:"active_bans"`
	Truncated   bool            `json:"active_bans_truncated"`
}

type listInfo struct {
	Path    string   `json:"path"`
	Entries int      `json:"entries"`
	CIDRs   []string `json:"cidrs"`
}

type banFileInfo struct {
	Path        string    `json:"path"`
	Entries     int       `json:"entries"`
	LastWritten time.Time `json:"last_written"`
}

type pathInfo struct {
	Path string `json:"path"`
}

// uaListsStats reports User-Agent list activity: cumulative request hits and
// the currently tracked (window-aligned, TTL-purged) IP set sizes.
type uaListsStats struct {
	WhitelistHitsTotal uint64 `json:"whitelist_hits_total"`
	BlacklistHitsTotal uint64 `json:"blacklist_hits_total"`
	ActiveWhitelistIPs int    `json:"active_whitelist_ips"`
	ActiveBlacklistIPs int    `json:"active_blacklist_ips"`
}

type listsStats struct {
	Whitelist      listInfo     `json:"whitelist"`
	Blacklist      listInfo     `json:"blacklist"`
	UserAgentLists uaListsStats `json:"user_agent_lists"`
	BanFile        banFileInfo  `json:"ban_file"`
	JailFile       pathInfo     `json:"jail_file"`
}

type loopStats struct {
	Iterations      uint64 `json:"iterations"`
	HeartbeatsTotal uint64 `json:"heartbeats_total"`
	LastDurationMS  int64  `json:"last_duration_ms"`
	SleepS          int    `json:"sleep_s"`
}

// liveStatsState is the loop-owned (single-goroutine) state behind snapshot
// building: iteration counter, last ban-file content actually on disk, and
// the cached top-talker slices (replaced wholesale, never mutated in place).
type liveStatsState struct {
	startTime      time.Time
	iterations     uint64
	heartbeats     uint64
	banContent     string
	banEntries     int
	banLastWritten time.Time
	topTalkers     [][]sliding.TopTalker // indexed like the windows slice
	lists          listsStats            // skeleton built once; list slices alias the startup-loaded CIDRs (never mutated)

	// User-Agent list counters, written by the loop goroutine only.
	uaWhitelistHits      uint64
	uaBlacklistHits      uint64
	uaActiveWhitelistIPs int
	uaActiveBlacklistIPs int
}

func newLiveStatsState(cfg *config.Config, whitelistCIDRs, blacklistCIDRs []string) *liveStatsState {
	var wlPath, blPath string
	if cfg.Global != nil {
		wlPath = cfg.Global.Whitelist
		blPath = cfg.Global.Blacklist
	}
	return &liveStatsState{
		startTime: time.Now(),
		lists: listsStats{
			Whitelist: listInfo{Path: wlPath, Entries: len(whitelistCIDRs), CIDRs: capCIDRList(whitelistCIDRs)},
			Blacklist: listInfo{Path: blPath, Entries: len(blacklistCIDRs), CIDRs: capCIDRList(blacklistCIDRs)},
			BanFile:   banFileInfo{Path: cfg.GetBanFile()},
			JailFile:  pathInfo{Path: cfg.GetJailFile()},
		},
	}
}

func capCIDRList(cidrs []string) []string {
	if len(cidrs) > maxListCIDRsInSnapshot {
		return cidrs[:maxListCIDRsInSnapshot]
	}
	return cidrs
}

// recordBanFileWrite is called after a SUCCESSFUL ban-file write so /bans
// always serves the last content actually on disk.
func (st *liveStatsState) recordBanFileWrite(content string, entries int) {
	st.banContent = content
	st.banEntries = entries
	st.banLastWritten = time.Now()
}

// newClusterSetStats wraps one arg set's iteration result. detected is a
// freshly built per-set slice whose backing array the snapshot owns.
func newClusterSetStats(argSet config.ClusterArgSet, useForJail bool, duration time.Duration, detected []output.LiveCIDR) clusterSetStats {
	return clusterSetStats{
		Params: clusterParams{
			MinSize:   argSet.MinClusterSize,
			Depth:     fmt.Sprintf("%d-%d", argSet.MinDepth, argSet.MaxDepth),
			Threshold: argSet.MeanSubnetDifference,
		},
		UseForJail:     useForJail,
		LastDurationUS: duration.Microseconds(),
		DetectedNow:    detected,
	}
}

// buildSnapshot assembles the immutable per-iteration snapshot. Called from
// the loop goroutine only; everything reachable from the returned snapshot is
// either freshly allocated here, immutable (strings), or never mutated after
// startup (list CIDR slices). heartbeat snapshots (idle loop) do not count
// as iterations and reuse the cached top-talker slices.
func buildSnapshot(
	st *liveStatsState,
	ing ingestor.Ingestor,
	cfg *config.Config,
	windows []slidingWindowInstance,
	winClusterStats [][]clusterSetStats,
	j *jail.Jail,
	loopDuration time.Duration,
	sleepS int,
	heartbeat bool,
) *statsSnapshot {
	if heartbeat {
		st.heartbeats++
	} else {
		st.iterations++

		topN := 0
		if cfg.Live != nil {
			topN = cfg.Live.TopTalkers
		}
		if topN > 0 && (st.iterations-1)%topTalkersInterval == 0 {
			if st.topTalkers == nil {
				st.topTalkers = make([][]sliding.TopTalker, len(windows))
			}
			for i := range windows {
				st.topTalkers[i] = windows[i].window.TopTalkers(topN)
			}
		}
	}

	ingSt := ing.Stats()
	now := time.Now()
	lists := st.lists
	lists.UserAgentLists = uaListsStats{
		WhitelistHitsTotal: st.uaWhitelistHits,
		BlacklistHitsTotal: st.uaBlacklistHits,
		ActiveWhitelistIPs: st.uaActiveWhitelistIPs,
		ActiveBlacklistIPs: st.uaActiveBlacklistIPs,
	}
	snap := &statsSnapshot{
		SchemaVersion: statsSchemaVersion,
		GeneratedAt:   now,
		UptimeS:       int64(now.Sub(st.startTime).Seconds()),
		Ingest: ingestStats{
			Connected:            !ing.IsClosed(),
			QueueDepth:           ingSt.QueueDepth,
			LastBatchAt:          ingSt.LastBatchAt,
			BatchesTotal:         ingSt.BatchesTotal,
			RequestsTotal:        ingSt.RequestsTotal,
			ParseErrorsTotal:     ingSt.ParseErrorsTotal,
			MalformedFieldsTotal: ingSt.MalformedFieldsTotal,
		},
		Lists: lists,
		Loop: loopStats{
			Iterations:      st.iterations,
			HeartbeatsTotal: st.heartbeats,
			LastDurationMS:  loopDuration.Milliseconds(),
			SleepS:          sleepS,
		},
		banFileContent: st.banContent,
	}
	snap.Lists.BanFile.Entries = st.banEntries
	snap.Lists.BanFile.LastWritten = st.banLastWritten

	snap.Windows = make([]windowStats, len(windows))
	for i := range windows {
		w := &windows[i]
		ws := windowStats{
			Name:                  w.name,
			SizeIPs:               int(w.window.IPStats.Len()),
			Requests:              len(w.window.IPQueue),
			AcceptedTotal:         w.acceptedTotal,
			RejectedByFilterTotal: w.rejectedTotal,
		}
		if winClusterStats != nil {
			ws.ClusterSets = winClusterStats[i]
		}
		if st.topTalkers != nil {
			ws.TopTalkers = st.topTalkers[i]
		}
		snap.Windows[i] = ws
	}

	bans := j.ListActiveBansWithMeta()
	js := jailStats{
		TotalActive: len(bans),
		Stages:      make([]jailStage, len(j.Cells)),
	}
	for i := range j.Cells {
		cell := &j.Cells[i]
		active := 0
		for k := range cell.Prisoners {
			if cell.Prisoners[k].BanActive {
				active++
			}
		}
		js.Stages[i] = jailStage{
			Stage:       cell.ID,
			BanDuration: cell.BanDuration.String(),
			Active:      active,
		}
	}
	if len(bans) > maxActiveBansInSnapshot {
		bans = bans[:maxActiveBansInSnapshot]
		js.Truncated = true
	}
	js.ActiveBans = make([]activeBanJSON, len(bans))
	for i, b := range bans {
		js.ActiveBans[i] = activeBanJSON{
			CIDR:      b.CIDR,
			Stage:     b.Stage,
			BanStart:  b.BanStart,
			ExpiresAt: b.ExpiresAt,
		}
	}
	snap.Jail = js

	return snap
}
