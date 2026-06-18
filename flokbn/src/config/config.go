package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ChristianF88/flokbn/config/regexprefilter"
	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/jail"
	"github.com/ChristianF88/flokbn/logging"
	"github.com/ChristianF88/flokbn/logparser"
)

var HomeDir string = os.Getenv("HOME")
var JailFile string = filepath.Join(HomeDir, "jail.json")
var BanFile string = filepath.Join(HomeDir, "banFile.txt")

type GlobalConfig struct {
	JailFile           string `toml:"jailFile"`
	BanFile            string `toml:"banFile"`
	Whitelist          string `toml:"whitelist"`
	Blacklist          string `toml:"blacklist"`
	UserAgentWhitelist string `toml:"userAgentWhitelist"`
	UserAgentBlacklist string `toml:"userAgentBlacklist"`
}

// ClusterArgSet represents a single set of clustering parameters with proper types
type ClusterArgSet struct {
	MinClusterSize       uint32
	MinDepth             uint32
	MaxDepth             uint32
	MeanSubnetDifference float64
}

type TrieConfig struct {
	UserAgentRegex string     `toml:"useragentRegex"`
	EndpointRegex  string     `toml:"endpointRegex"`
	StartTime      *time.Time `toml:"startTime"`
	EndTime        *time.Time `toml:"endTime"`
	CIDRRanges     []string   `toml:"cidrRanges"`
	ClusterArgSets []ClusterArgSet
	UseForJail     []bool `toml:"useForJail"`

	// URGENT-09: whether the corresponding bound carried an EXPLICIT timezone
	// offset. When true, the bound is compared as a TRUE INSTANT; when false
	// (the default, zone-less bound), comparison is wall-clock / zone-agnostic so
	// a bound "06:00" matches a log line whose local clock reads 06:00 regardless
	// of the log's offset.
	StartTimeHasOffset bool `toml:"-"`
	EndTimeHasOffset   bool `toml:"-"`

	// Original timestamp literal as written in the config, captured whenever the
	// key was present and non-empty (on parse failure and on success). Unexported.
	// Validate's format check is `startTimeRaw != "" && StartTime == nil`; the
	// range diagnostic echoes these literals rather than a normalized round-trip.
	startTimeRaw string
	endTimeRaw   string

	// Compiled regex patterns for fast filtering
	userAgentRegexCompiled *regexp.Regexp
	endpointRegexCompiled  *regexp.Regexp

	// Required-literal prefilters screen inputs before the regex runs.
	// nil means no prefilter is available (run the regex directly).
	userAgentPrefilter *regexprefilter.Prefilter
	endpointPrefilter  *regexprefilter.Prefilter

	// CFG-02 collect-all guard flags. Set true whenever
	// parseClusterArgSetsFromTOML / parseUseForJail emitted ANY diagnostic for
	// this trie. validateUseForJailAlignment SKIPS the alignment check when
	// EITHER is true (a dropped clusterArgSets row or a dropped useForJail
	// element shortens its slice and would emit a SPURIOUS second mismatch).
	clusterArgSetsHadError bool
	useForJailHadError     bool
}

type SlidingTrieConfig struct {
	UserAgentRegex         string        `toml:"useragentRegex"`
	EndpointRegex          string        `toml:"endpointRegex"`
	SlidingWindowMaxTime   time.Duration `toml:"slidingWindowMaxTime"`
	SlidingWindowMaxSize   int           `toml:"slidingWindowMaxSize"`
	SleepBetweenIterations int           `toml:"sleepBetweenIterations"`
	ClusterArgSets         []ClusterArgSet
	UseForJail             []bool `toml:"useForJail"`

	// Sliding tries do not consume these bounds for filtering (the window is
	// time-bounded by SlidingWindowMaxTime); they exist only so Validate(LiveMode)
	// can surface a malformed or inverted [live.<name>] startTime/endTime, parsed
	// identically to a [static.<name>] bound.
	StartTime          *time.Time `toml:"-"`
	EndTime            *time.Time `toml:"-"`
	StartTimeHasOffset bool       `toml:"-"`
	EndTimeHasOffset   bool       `toml:"-"`
	// Original timestamp literal (see TrieConfig.startTimeRaw).
	startTimeRaw string
	endTimeRaw   string

	// Compiled regex patterns for fast filtering
	userAgentRegexCompiled *regexp.Regexp
	endpointRegexCompiled  *regexp.Regexp

	// Required-literal prefilters screen inputs before the regex runs.
	// nil means no prefilter is available (run the regex directly).
	userAgentPrefilter *regexprefilter.Prefilter
	endpointPrefilter  *regexprefilter.Prefilter

	// CFG-02 collect-all guard flags (see TrieConfig).
	clusterArgSetsHadError bool
	useForJailHadError     bool
}

type StaticConfig struct {
	LogFile   string `toml:"logFile"`
	LogFormat string `toml:"logFormat"`
	PlotPath  string `toml:"plotPath"`
}

type LiveConfig struct {
	Port        string        `toml:"port"`
	ReadTimeout time.Duration `toml:"readTimeout"`
	StatsListen string        `toml:"statsListen"` // host:port for the /stats HTTP server; empty = off
	TopTalkers  int           `toml:"topTalkers"`  // top-N IPs per window in /stats; 0 = off
}

// LogConfig configures the [log] section: leveled slog output on stderr.
// Empty values use the defaults (level "info", format "text").
type LogConfig struct {
	Level  string `toml:"level"`  // debug, info, warn, error
	Format string `toml:"format"` // text, json
}

// DefaultLiveReadTimeout is the TCP ingestor read timeout used when the
// [live] section does not specify a readTimeout.
const DefaultLiveReadTimeout = 5 * time.Second

// globalScalarKeys are the recognized keys of the [global] section. It backs
// the valid-set hint on parseGlobalConfig's unknown-key rejection (via
// wantKeysFromSet); parseGlobalConfig's own dispatch is a hardcoded switch and
// does not read this map.
var globalScalarKeys = map[string]struct{}{
	"jailFile":           {},
	"banFile":            {},
	"whitelist":          {},
	"blacklist":          {},
	"userAgentWhitelist": {},
	"userAgentBlacklist": {},
}

// staticScalarKeys are the recognized scalar keys of the [static] section.
// Any other [static] sub-key is treated as a trie sub-table. This set is the
// single source of truth shared by LoadConfig's dispatch and parseStaticConfig's
// strict unknown-key check, so the two cannot drift.
var staticScalarKeys = map[string]struct{}{
	"logFile":   {},
	"logFormat": {},
	"plotPath":  {},
}

// liveScalarKeys are the recognized scalar keys of the [live] section. Any
// other [live] sub-key is treated as a sliding-trie sub-table. Used by
// LoadConfig's dispatch to split [live] scalars from sliding-trie sub-tables;
// parseLiveConfig's strict unknown-key check uses the narrower liveSectionKeys.
var liveScalarKeys = map[string]struct{}{
	"port":                   {},
	"readTimeout":            {},
	"statsListen":            {},
	"topTalkers":             {},
	"slidingWindowMaxTime":   {},
	"slidingWindowMaxSize":   {},
	"sleepBetweenIterations": {},
}

// liveSectionKeys are the scalar keys parseLiveConfig actually accepts on the
// [live] table itself (a subset of liveScalarKeys: the remaining liveScalarKeys
// are sliding-trie params consumed under [live.<name>], not on [live]). It backs
// the valid-set hint on parseLiveConfig's unknown-key rejection.
var liveSectionKeys = map[string]struct{}{
	"port":        {},
	"readTimeout": {},
	"statsListen": {},
	"topTalkers":  {},
}

// logScalarKeys are the recognized keys of the [log] section. It backs the
// valid-set hint on parseLogConfig's unknown-key rejection.
var logScalarKeys = map[string]struct{}{
	"level":  {},
	"format": {},
}

// trieKeys are the recognized keys of a [static.<name>] trie sub-table.
var trieKeys = map[string]struct{}{
	"useragentRegex": {},
	"endpointRegex":  {},
	"startTime":      {},
	"endTime":        {},
	"cidrRanges":     {},
	"clusterArgSets": {},
	"useForJail":     {},
}

// slidingTrieKeys are the recognized keys of a [live.<name>] sliding-trie
// sub-table: the trie filter keys plus the per-window sliding parameters.
// startTime/endTime/cidrRanges are accepted (parity with the static trie key
// surface) but not consumed by sliding tries; this matches the prior tolerant
// behavior so a config that set them does not start failing now.
var slidingTrieKeys = map[string]struct{}{
	"useragentRegex":         {},
	"endpointRegex":          {},
	"startTime":              {},
	"endTime":                {},
	"cidrRanges":             {},
	"clusterArgSets":         {},
	"useForJail":             {},
	"slidingWindowMaxTime":   {},
	"slidingWindowMaxSize":   {},
	"sleepBetweenIterations": {},
}

type Config struct {
	Global *GlobalConfig `toml:"global"`
	Static *StaticConfig `toml:"static"`
	Live   *LiveConfig   `toml:"live"`
	Log    *LogConfig    `toml:"log"`

	// StaticTries and LiveTries are NOT struct-decoded. They are the trie
	// sub-tables nested under [static.<name>] / [live.<name>], which LoadConfig
	// parses by hand from a map[string]any (see the dispatch loops there). The
	// `toml:"-"` tag documents that these fields are never populated by
	// toml.Decode; a previous `,remain` tag here was dead and misleading —
	// BurntSushi/toml populated neither (two `,remain` fields cannot both win),
	// so a refactor to toml.Decode(data, cfg) would have silently lost every
	// trie. Keep the hand-parsing; do not reintroduce a decode tag.
	StaticTries map[string]*TrieConfig        `toml:"-"`
	LiveTries   map[string]*SlidingTrieConfig `toml:"-"`

	// diags accumulates the parse-phase + flags-handler-injected diagnostics
	// (CFG-02). It is NOT a package global — it is allocated at the top of
	// LoadConfig and threaded by-pointer into every parse* function, and the
	// flags handlers append into it directly. Validate(mode) COPIES these
	// messages (read-only on cfg.diags) into a fresh local accumulator and
	// appends its own validate-phase checks there, so Validate is idempotent and
	// cfg.diags never accumulates across calls. A hand-built Config (flags mode
	// or tests) may leave this nil; ensureDiags allocates lazily.
	diags *ConfigDiagnostics
}

// Diagnostics returns the persistent parse/flags-phase accumulator, allocating
// it on first use. The CLI flags handlers append regex/cidrRanges diagnostics
// here so the single barrier (which calls Validate, which copies these) reports
// them. Validate never mutates the returned accumulator.
func (c *Config) Diagnostics() *ConfigDiagnostics {
	if c.diags == nil {
		c.diags = &ConfigDiagnostics{}
	}
	return c.diags
}

// RunMode selects which trie map Validate inspects: StaticMode walks
// StaticTries, LiveMode walks LiveTries. The shared Validate pass runs for both
// --config and flags modes of each command (one pass per command).
type RunMode int

const (
	StaticMode RunMode = iota
	LiveMode
)

// Validate runs the user-value config diagnostics for the given run mode and
// returns a FRESH accumulator. It is COLLECT-ALL (never early-returns), so one
// pass surfaces every problem at once.
//
// CONTRACT (CFG-02, tested by the idempotency test):
//   - Validate COPIES the persistent cfg.diags (parse-phase + flags-handler
//     messages) into a fresh LOCAL accumulator (read-only on cfg.diags — never
//     appends into it).
//   - It then APPENDS its own validate-phase checks into the LOCAL accumulator
//     only: trie timestamps (CFG-01), the effective logFormat (StaticMode),
//     the configured list files (both modes), and validateLiveInto (LiveMode).
//   - Because it never mutates cfg.diags and every check is deterministic,
//     calling Validate twice yields identical Len() and identical Report().
//
// I/O: Validate is NO LONGER pure — it READS the configured whitelist/blacklist/
// UA-list files and the log format. It remains side-effect-free w.r.t. on-disk
// state (it only reads). It is called EXACTLY ONCE per run, at the barrier seam
// in executeStaticAnalysis / executeLiveAnalysis.
//
// NIL-SAFETY: Validate derefs c.Static for the logFormat + logfile-exists checks
// (guarded by `if c.Static != nil`) and calls validateLiveInto (which guards a
// nil c.Live / c.Global). The list-file wrappers internally guard a nil
// c.Global. After LoadConfig all four sections are non-nil; a hand-built Config
// (flags mode, tests) may pass nil and is handled by these guards.
func (c *Config) Validate(mode RunMode) *ConfigDiagnostics {
	// Copy the persistent parse/flags-phase messages into a fresh local; never
	// mutate cfg.diags (idempotency contract).
	diags := &ConfigDiagnostics{}
	if c.diags != nil {
		diags.msgs = append(diags.msgs, c.diags.msgs...)
	}

	switch mode {
	case StaticMode:
		for name, tc := range c.StaticTries {
			if tc == nil {
				continue
			}
			validateTrieTimestamps(diags, "static."+name,
				tc.startTimeRaw, tc.endTimeRaw,
				tc.StartTime, tc.EndTime,
				tc.StartTimeHasOffset, tc.EndTimeHasOffset)
			validateUseForJailAlignment("static."+name,
				tc.ClusterArgSets, tc.UseForJail,
				tc.clusterArgSetsHadError, tc.useForJailHadError, diags)
		}
		// logFormat: the SAME empty->default fallback analysis applies (an empty
		// logFormat is valid; the default is used). validateFormat("") FAILS for
		// the missing %h, so the fallback MUST precede the check.
		if c.Static != nil {
			effFormat := c.Static.LogFormat
			if effFormat == "" {
				effFormat = logparser.DefaultLogFormat
			}
			if err := logparser.ValidateFormat(effFormat); err != nil {
				diags.Add("static", "logFormat", c.Static.LogFormat,
					"a valid log format string with exactly one %h", err)
			}
			// logFile-exists migrated from the CLI handler (CFG-02): a configured
			// but absent logfile enumerates alongside (e.g.) a bad startTime instead
			// of a stat short-circuit winning before the barrier. The empty
			// "required" case is recorded by the config-mode handler into cfg.diags
			// (which this pass copies) so trie-fragment unit tests that drive
			// Validate directly without a logFile stay diagnostic-free.
			if c.Static.LogFile != "" {
				if _, err := os.Stat(c.Static.LogFile); os.IsNotExist(err) {
					diags.AddRaw(fmt.Sprintf("[static] logFile %s does not exist", quoteCapped(c.Static.LogFile)))
				}
			}
			// plotPath dir-exists migrated from the CLI handler (CFG-02).
			if msg := plotPathDiagnostic(c.Static.PlotPath); msg != "" {
				diags.AddRaw(msg)
			}
		}
		c.validateListFiles(diags)
		// Static processes the jail only when both jailFile and banFile are set
		// (see ProcessJailWithWhitelist's guard); validate the jail at the barrier
		// only when it will actually be loaded.
		if c.Global != nil && c.Global.JailFile != "" && c.Global.BanFile != "" {
			c.validateJailFile(diags)
		}
	case LiveMode:
		for name, stc := range c.LiveTries {
			if stc == nil {
				continue
			}
			validateTrieTimestamps(diags, "live."+name,
				stc.startTimeRaw, stc.endTimeRaw,
				stc.StartTime, stc.EndTime,
				stc.StartTimeHasOffset, stc.EndTimeHasOffset)
			validateUseForJailAlignment("live."+name,
				stc.ClusterArgSets, stc.UseForJail,
				stc.clusterArgSetsHadError, stc.useForJailHadError, diags)
		}
		c.validateLiveInto(diags)
		c.validateListFiles(diags)
		// Live always loads the jail (runLiveLoop reads it unconditionally), so
		// validate it at the barrier in every live run.
		c.validateJailFile(diags)
	}
	return diags
}

// plotPathDiagnostic returns a non-empty diagnostic line when a configured
// plotPath's directory does not exist (the dir-exists check migrated from the
// CLI handler). The cwd lookup mirrors the old validatePlotPath. The plotDir is
// quoteCapped (untrusted). Empty plotPath => no plot requested => no diagnostic.
func plotPathDiagnostic(plotPath string) string {
	if plotPath == "" {
		return ""
	}
	plotDir := filepath.Dir(plotPath)
	if plotDir == "." {
		if wd, err := os.Getwd(); err == nil {
			plotDir = wd
		}
	}
	if _, err := os.Stat(plotDir); os.IsNotExist(err) {
		return fmt.Sprintf("[static] plotPath directory %s does not exist", quoteCapped(plotDir))
	}
	return ""
}

// validateListFiles loads each configured global list (whitelist/blacklist/UA
// whitelist/UA blacklist) through the SAME loaders the enforcers use, routing a
// cannot-open / cannot-read / IPv6 / malformed-CIDR failure into diags as a
// verbatim AddRaw line (the loader error text already quotes the path and
// offending value with the unified grammar). This is the SOLE list-load-for-
// validation site: the flags handler must NOT also load lists (that would
// double-count). The list bytes validated here are read again by the downstream
// enforcers (runLiveLoop / computeGlobalFilters / ProcessJailWithWhitelist); the
// 2-3x read with a TOCTOU window is accepted (documented in the commit body) —
// the barrier's job is to catch a structurally broken/unreadable list at start.
//
// The c.Global wrappers internally guard a nil c.Global and an empty path, so a
// nil/absent [global] section yields zero list-file diagnostics.
func (c *Config) validateListFiles(diags *ConfigDiagnostics) {
	if _, err := c.LoadWhitelistCIDRs(); err != nil {
		diags.AddRaw(err.Error())
	}
	if _, err := c.LoadBlacklistCIDRs(); err != nil {
		diags.AddRaw(err.Error())
	}
	if _, err := c.LoadUserAgentWhitelistPatterns(); err != nil {
		diags.AddRaw(err.Error())
	}
	if _, err := c.LoadUserAgentBlacklistPatterns(); err != nil {
		diags.AddRaw(err.Error())
	}
}

// validateJailFile surfaces an unloadable jail (unreadable / invalid-JSON /
// zero-cell) at the barrier via the SAME loader the run uses, so it aborts
// before any work instead of the static path silently swallowing it. A
// missing/empty jail is a valid fresh start and records nothing. It is a load
// error to surface (operator-visible on-disk state), not a panic; the loader
// error already names the path.
func (c *Config) validateJailFile(diags *ConfigDiagnostics) {
	if _, err := jail.FileToJail(c.GetJailFile()); err != nil {
		diags.AddRaw(err.Error())
	}
}

// validateTrieTimestamps runs the (a) startTime-format, (b) endTime-format, and
// (c) endTime<startTime range checks for one trie, in that order, with NO early
// return: a single trie with BOTH a bad startTime AND a bad endTime yields TWO
// messages. The section is passed WITHOUT brackets (Add/AddRange add them) and
// matches the unknown-key grammar prefix ("static."+name / "live."+name).
func validateTrieTimestamps(diags *ConfigDiagnostics, section string,
	startRaw, endRaw string, start, end *time.Time, startHasOffset, endHasOffset bool) {

	// Format: raw captured (non-empty) but never parsed => RFC3339 failure.
	if startRaw != "" && start == nil {
		diags.Add(section, "startTime", startRaw, "RFC3339 (e.g. 2025-01-01T00:00:00Z)", nil)
	}
	if endRaw != "" && end == nil {
		diags.Add(section, "endTime", endRaw, "RFC3339 (e.g. 2025-01-01T00:00:00Z)", nil)
	}
	// Range: only when both bounds parsed. The offset-equality gate matches
	// makeTimeBounds (URGENT-09): a zone-less wall-clock bound and an
	// offset-bearing instant are not comparable via time.Before, so skip then.
	if start != nil && end != nil && startHasOffset == endHasOffset && end.Before(*start) {
		diags.AddRange(section, endRaw, startRaw)
	}
}

func LoadConfig(configPath string) (*Config, error) {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var rawConfig map[string]any
	if _, err := toml.Decode(string(configData), &rawConfig); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	config := &Config{
		StaticTries: make(map[string]*TrieConfig),
		LiveTries:   make(map[string]*SlidingTrieConfig),
		diags:       &ConfigDiagnostics{},
	}
	diags := config.diags

	for key, value := range rawConfig {
		switch key {
		case "global":
			if globalMap, ok := value.(map[string]any); ok {
				globalConfig, err := parseGlobalConfig(globalMap, diags)
				if err != nil {
					return nil, fmt.Errorf("parsing global config: %w", err)
				}
				config.Global = globalConfig
			}
		case "static":
			if staticMap, ok := value.(map[string]any); ok {
				staticConfig, err := parseStaticConfig(staticMap, diags)
				if err != nil {
					return nil, fmt.Errorf("parsing static config: %w", err)
				}
				config.Static = staticConfig
				// Parse static tries from nested config. Only the recognized
				// scalar keys (staticScalarKeys — the same set parseStaticConfig
				// checks against) are section fields; everything else is a trie
				// sub-table. Deriving both from one set keeps the strict
				// unknown-key check and this dispatch from drifting apart.
				for subKey, subValue := range staticMap {
					if _, isScalar := staticScalarKeys[subKey]; isScalar {
						continue
					}
					if trieMap, ok := subValue.(map[string]any); ok {
						trieConfig, err := parseTrieConfig(subKey, trieMap, diags)
						if err != nil {
							return nil, fmt.Errorf("parsing trie config %q: %w", subKey, err)
						}
						if trieConfig != nil {
							config.StaticTries[subKey] = trieConfig
						}
					}
				}
			}
		case "log":
			if logMap, ok := value.(map[string]any); ok {
				logConfig, err := parseLogConfig(logMap, diags)
				if err != nil {
					return nil, fmt.Errorf("parsing log config: %w", err)
				}
				config.Log = logConfig
			}
		case "live":
			if liveMap, ok := value.(map[string]any); ok {
				liveConfig, err := parseLiveConfig(liveMap, diags)
				if err != nil {
					return nil, fmt.Errorf("parsing live config: %w", err)
				}
				config.Live = liveConfig
				// Parse live tries from nested config. Only the recognized
				// scalar keys (liveScalarKeys) are section fields; everything
				// else is a sliding-trie sub-table. (parseLiveConfig validates
				// the narrower [live]-table set, liveSectionKeys.)
				for subKey, subValue := range liveMap {
					if _, isScalar := liveScalarKeys[subKey]; isScalar {
						continue
					}
					if trieMap, ok := subValue.(map[string]any); ok {
						trieConfig, err := parseSlidingTrieConfig(subKey, trieMap, diags)
						if err != nil {
							return nil, fmt.Errorf("parsing sliding trie config %q: %w", subKey, err)
						}
						if trieConfig != nil {
							config.LiveTries[subKey] = trieConfig
						}
					}
				}
			}
		default:
			// A misspelled top-level section header ([gloabl], [satic]) decodes
			// into rawConfig under a key matching no case. Without this guard it
			// is silently dropped, leaving the intended section an empty struct
			// and (e.g.) nullifying whitelist/blacklist filtering while the run
			// reports success. Fail loud, naming the unknown section. Absent
			// optional sections never appear as keys here, so omission stays valid.
			//
			// Deliberate asymmetry: a misspelled top-level SECTION stays a hard
			// returned error, NOT a collect-all diagnostic — it loses an ENTIRE
			// section (a fail-OPEN, e.g. a swallowed [global] nullifies whitelist
			// filtering), structurally distinct from a misspelled KEY within a
			// recognized section (which IS migrated to diagnostics). The unknown-key
			// checks collect; the unknown-section guard fails fast.
			return nil, fmt.Errorf("unknown top-level section %q (want [global], [static], [live], [log], and [static.<name>]/[live.<name>] tables)", key)
		}
	}

	if config.Global == nil {
		config.Global = &GlobalConfig{}
	}
	if config.Static == nil {
		config.Static = &StaticConfig{}
	}
	if config.Live == nil {
		config.Live = &LiveConfig{}
	}
	if config.Log == nil {
		config.Log = &LogConfig{}
	}

	return config, nil
}

// parseGlobalConfig parses the [global] section. Wrong-typed recognized keys
// stay HARD errors at load time (structural, like TOML syntax). Unknown/
// misspelled keys are COLLECT-ALL diagnostics (CFG-02): each is recorded and
// parsing continues, so one pass surfaces every typo.
func parseGlobalConfig(m map[string]any, diags *ConfigDiagnostics) (*GlobalConfig, error) {
	config := &GlobalConfig{}
	stringField := func(key string, dst *string) error {
		v, ok := m[key].(string)
		if !ok {
			return fmt.Errorf("%s must be a string, got %T", key, m[key])
		}
		*dst = v
		return nil
	}
	for key := range m {
		var err error
		switch key {
		case "jailFile":
			err = stringField(key, &config.JailFile)
		case "banFile":
			err = stringField(key, &config.BanFile)
		case "whitelist":
			err = stringField(key, &config.Whitelist)
		case "blacklist":
			err = stringField(key, &config.Blacklist)
		case "userAgentWhitelist":
			err = stringField(key, &config.UserAgentWhitelist)
		case "userAgentBlacklist":
			err = stringField(key, &config.UserAgentBlacklist)
		default:
			diags.AddRaw(fmt.Sprintf("unknown key %s in [global] section %s", quoteCapped(key), wantKeysFromSet(globalScalarKeys)))
			continue
		}
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}

// parseStaticConfig parses the [static] section's scalar fields. Trie
// sub-tables (map values) are handled by LoadConfig; only the recognized
// scalar keys are validated here. Wrong-typed scalars stay HARD errors; unknown
// keys are COLLECT-ALL diagnostics (CFG-02).
func parseStaticConfig(m map[string]any, diags *ConfigDiagnostics) (*StaticConfig, error) {
	config := &StaticConfig{}
	stringField := func(key string, dst *string) error {
		v, ok := m[key].(string)
		if !ok {
			return fmt.Errorf("%s must be a string, got %T", key, m[key])
		}
		*dst = v
		return nil
	}
	for key, value := range m {
		// Sub-tables are trie sections, dispatched separately by LoadConfig.
		if _, isTable := value.(map[string]any); isTable {
			continue
		}
		var err error
		switch key {
		case "logFile":
			err = stringField(key, &config.LogFile)
		case "logFormat":
			err = stringField(key, &config.LogFormat)
		case "plotPath":
			err = stringField(key, &config.PlotPath)
		default:
			diags.AddRaw(fmt.Sprintf("unknown key %s in [static] section %s", quoteCapped(key), wantKeysFromSet(staticScalarKeys)))
			continue
		}
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}

// parseLiveConfig parses the [live] section's scalar fields. Sliding-trie
// sub-tables are handled by LoadConfig. Wrong-typed recognized scalars and
// unknown keys are hard errors: e.g. port = 8080 (an integer) now fails at load
// instead of leaving Port="" and surfacing a misleading "port is required".
func parseLiveConfig(m map[string]any, diags *ConfigDiagnostics) (*LiveConfig, error) {
	config := &LiveConfig{}
	for key, value := range m {
		// Sub-tables are sliding-trie sections, dispatched separately.
		if _, isTable := value.(map[string]any); isTable {
			continue
		}
		switch key {
		case "port":
			v, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("port must be a string, got %T", value)
			}
			config.Port = v
		case "readTimeout":
			v, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("readTimeout must be a string, got %T", value)
			}
			// Malformed duration stays a hard LoadConfig error: structurally
			// analogous to a wrong-type scalar, NOT migrated to diagnostics.
			duration, err := time.ParseDuration(v)
			if err != nil {
				return nil, fmt.Errorf("invalid readTimeout %q: %w", v, err)
			}
			config.ReadTimeout = duration
		case "statsListen":
			v, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("statsListen must be a string, got %T", value)
			}
			config.StatsListen = v
		case "topTalkers":
			v, ok := value.(int64)
			if !ok {
				return nil, fmt.Errorf("topTalkers must be an integer, got %T", value)
			}
			config.TopTalkers = int(v)
		default:
			diags.AddRaw(fmt.Sprintf("unknown key %s in [live] section %s", quoteCapped(key), wantKeysFromSet(liveSectionKeys)))
			continue
		}
	}
	return config, nil
}

// parseLogConfig parses the [log] section. Unknown keys are rejected so a
// typo (e.g. "lvl") fails loud instead of silently using defaults, and the
// level/format enums are validated via the logging package (the canonical
// rules the logger itself applies).
func parseLogConfig(m map[string]any, diags *ConfigDiagnostics) (*LogConfig, error) {
	config := &LogConfig{}
	for key, value := range m {
		switch key {
		case "level":
			v, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("level must be a string, got %T", value)
			}
			config.Level = v
		case "format":
			v, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("format must be a string, got %T", value)
			}
			config.Format = v
		default:
			diags.AddRaw(fmt.Sprintf("unknown key %s in [log] section %s", quoteCapped(key), wantKeysFromSet(logScalarKeys)))
			continue
		}
	}
	// Level/format enum (a value-enum check) is COLLECT-ALL (CFG-02): record and
	// continue instead of returning the first failure.
	if err := logging.Validate(config.Level, config.Format); err != nil {
		diags.AddRaw(err.Error())
	}
	return config, nil
}

// parseRegexFields extracts and sets regex strings from a TOML map.
// A present-but-wrong-typed value is a hard error (fail-loud at load).
func parseRegexFields(m map[string]any) (useragentRegex, endpointRegex string, err error) {
	if v, present := m["useragentRegex"]; present {
		s, ok := v.(string)
		if !ok {
			return "", "", fmt.Errorf("useragentRegex must be a string, got %T", v)
		}
		useragentRegex = s
	}
	if v, present := m["endpointRegex"]; present {
		s, ok := v.(string)
		if !ok {
			return "", "", fmt.Errorf("endpointRegex must be a string, got %T", v)
		}
		endpointRegex = s
	}
	return useragentRegex, endpointRegex, nil
}

// wantKeysFromSet renders a recognized-key set as a deterministic
// "(want: a, b, c)" suffix for unknown-key errors. Keys are sorted so the
// emitted text is stable (tests assert on it). The valid set is always listed
// on a rejection so an operator knows exactly which key to use.
func wantKeysFromSet(allowed map[string]struct{}) string {
	keys := make([]string, 0, len(allowed))
	for k := range allowed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return "(want: " + strings.Join(keys, ", ") + ")"
}

// checkUnknownKeys records a diagnostic for EVERY key in m not in allowed,
// naming the offending key (quoteCapped, untrusted) and section AND listing the
// valid set. COLLECT-ALL (CFG-02): the loop already iterates ALL keys, so a
// trie with two misspelled keys surfaces both. Shared by the trie parsers.
func checkUnknownKeys(m map[string]any, allowed map[string]struct{}, section string, diags *ConfigDiagnostics) {
	for key := range m {
		if _, ok := allowed[key]; !ok {
			diags.AddRaw(fmt.Sprintf("unknown key %s in %s section %s", quoteCapped(key), section, wantKeysFromSet(allowed)))
		}
	}
}

// parseClusterArgSetsFromTOML parses cluster argument sets from TOML nested
// arrays. COLLECT-ALL (CFG-02): a malformed, under-specified, or out-of-range
// row records a diagnostic naming the offending row index and is SKIPPED,
// continuing to accumulate subsequent rows. It returns the surviving sets plus
// hadError=true if ANY row was dropped.
//
// INVARIANT (security): EVERY code path that drops/skips a row records a
// diagnostic — so len(diags additions)==0 implies every input row survived (no
// silent drop). A silent drop would shift the positional useForJail alignment
// (cli/api.go, analysis/static.go index argSet[i] against useForJail[i]) and
// disable operator-requested jail rules. The barrier ALWAYS aborts when a
// clusterArgSets diagnostic is present, so the surviving (shorter) slice never
// reaches analysis. A wrong-TYPE container (raw not []any) stays a HARD error.
func parseClusterArgSetsFromTOML(m map[string]any, section string, diags *ConfigDiagnostics) (sets []ClusterArgSet, hadError bool, err error) {
	raw, present := m["clusterArgSets"]
	if !present {
		return nil, false, nil
	}
	v, ok := raw.([]any)
	if !ok {
		return nil, false, fmt.Errorf("clusterArgSets must be an array of [minClusterSize,minDepth,maxDepth,meanSubnetDifference] rows, got %T", raw)
	}
	for i, item := range v {
		arr, ok := item.([]any)
		if !ok {
			diags.AddRaw(fmt.Sprintf("[%s] clusterArgSets row %d must be an array of 4 numbers, got %T", section, i, item))
			hadError = true
			continue
		}
		var argSet []float64
		badMember := false
		for _, val := range arr {
			switch f := val.(type) {
			case float64:
				argSet = append(argSet, f)
			case int64:
				argSet = append(argSet, float64(f))
			default:
				diags.AddRaw(fmt.Sprintf("[%s] clusterArgSets row %d contains a non-numeric value %s (%T)", section, i, quoteCapped(fmt.Sprintf("%v", val)), val))
				badMember = true
			}
		}
		if badMember {
			hadError = true
			continue
		}
		if len(argSet) != 4 {
			diags.AddRaw(fmt.Sprintf("[%s] clusterArgSets row %d requires exactly 4 numeric values (minClusterSize,minDepth,maxDepth,meanSubnetDifference), got %d", section, i, len(argSet)))
			hadError = true
			continue
		}
		minDepth := uint32(argSet[1])
		maxDepth := uint32(argSet[2])
		// 32 is the IPv4 bit width ceiling. Mirror the CLI REJECT
		// (ParseClusterArgSetsFromStrings) so an invalid set never reaches
		// collectCIDRsNode and the positional useForJail alignment is preserved.
		if minDepth > maxDepth {
			diags.AddRaw(fmt.Sprintf("[%s] clusterArgSets row %d: minDepth (%d) must be <= maxDepth (%d)", section, i, minDepth, maxDepth))
			hadError = true
			continue
		}
		if maxDepth > 32 {
			diags.AddRaw(fmt.Sprintf("[%s] clusterArgSets row %d: maxDepth (%d) must be <= 32", section, i, maxDepth))
			hadError = true
			continue
		}
		sets = append(sets, ClusterArgSet{
			MinClusterSize:       uint32(argSet[0]),
			MinDepth:             minDepth,
			MaxDepth:             maxDepth,
			MeanSubnetDifference: argSet[3],
		})
	}
	return sets, hadError, nil
}

// parseUseForJail parses the useForJail boolean array from a TOML map.
// Collect-all: a non-bool ELEMENT records a diagnostic and is SKIPPED, returning
// the survivors plus hadError=true. A non-array CONTAINER stays a HARD error. The
// alignment guard skips when hadError so a shortened survivor slice never emits a
// spurious second mismatch.
func parseUseForJail(m map[string]any, section string, diags *ConfigDiagnostics) (result []bool, hadError bool, err error) {
	raw, present := m["useForJail"]
	if !present {
		return nil, false, nil
	}
	v, ok := raw.([]any)
	if !ok {
		return nil, false, fmt.Errorf("useForJail must be an array of booleans, got %T", raw)
	}
	result = make([]bool, 0, len(v))
	for i, item := range v {
		b, ok := item.(bool)
		if !ok {
			diags.AddRaw(fmt.Sprintf("[%s] useForJail[%d] must be a boolean, got %T", section, i, item))
			hadError = true
			continue
		}
		result = append(result, b)
	}
	return result, hadError, nil
}

// parseTimeBound reads an RFC3339 timestamp bound (startTime/endTime) from a
// trie TOML map. A present-but-non-string value is a hard fail-fast (structural
// error); an empty or absent value yields the zero result, accepted as before.
// A non-empty string is returned as raw and, when it parses, as a non-nil
// instant with hasOffset=true (RFC3339 always carries a zone designator;
// URGENT-09). The raw literal is returned even on parse failure so Validate can
// echo the operator's text. Shared by both trie parsers so the static and
// sliding bound paths cannot drift.
func parseTimeBound(m map[string]any, key string) (raw string, t *time.Time, hasOffset bool, err error) {
	v, present := m[key]
	if !present {
		return "", nil, false, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", nil, false, fmt.Errorf("%s must be a string, got %T", key, v)
	}
	if s == "" {
		return "", nil, false, nil
	}
	if parsed, perr := time.Parse(time.RFC3339, s); perr == nil {
		return s, &parsed, true, nil
	}
	return s, nil, false, nil
}

func parseTrieConfig(name string, m map[string]any, diags *ConfigDiagnostics) (*TrieConfig, error) {
	section := "static." + name
	checkUnknownKeys(m, trieKeys, "["+section+"] trie", diags)
	uaRegex, epRegex, err := parseRegexFields(m)
	if err != nil {
		return nil, err
	}
	clusterArgSets, clusterHadError, err := parseClusterArgSetsFromTOML(m, section, diags)
	if err != nil {
		return nil, err
	}
	useForJail, useForJailHadError, err := parseUseForJail(m, section, diags)
	if err != nil {
		return nil, err
	}
	tc := &TrieConfig{
		UserAgentRegex:         uaRegex,
		EndpointRegex:          epRegex,
		ClusterArgSets:         clusterArgSets,
		UseForJail:             useForJail,
		clusterArgSetsHadError: clusterHadError,
		useForJailHadError:     useForJailHadError,
	}
	// ANTI-MISALIGNMENT (security): when a clusterArgSets row was dropped, the
	// surviving (shorter) slice must NOT be jailed by a mis-sized useForJail.
	// The barrier always aborts when a clusterArgSets diagnostic is present, so
	// this never reaches analysis — but clear UseForJail belt-and-suspenders so
	// even a hypothetical barrier-bypass cannot apply useForJail[i] to a shifted
	// survivor. The alignment check (in Validate) is skipped when either flag is
	// set, so it never emits a spurious second mismatch.
	if clusterHadError {
		tc.UseForJail = nil
	}
	tc.CompileRegexInto(diags)
	// A non-empty but non-RFC3339 startTime/endTime sets the raw carrier (not the
	// parsed pointer) and is surfaced as a diagnostic at Validate, not here; a
	// wrong-TYPE value stays a hard fail-fast. The raw literal is also captured
	// on success so the range diagnostic echoes the operator's original text.
	if tc.startTimeRaw, tc.StartTime, tc.StartTimeHasOffset, err = parseTimeBound(m, "startTime"); err != nil {
		return nil, err
	}
	if tc.endTimeRaw, tc.EndTime, tc.EndTimeHasOffset, err = parseTimeBound(m, "endTime"); err != nil {
		return nil, err
	}
	if v, present := m["cidrRanges"]; present {
		arr, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("cidrRanges must be an array of strings, got %T", v)
		}
		for i, item := range arr {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("cidrRanges[%d] must be a string, got %T", i, item)
			}
			// SECURITY: append ONLY valid IPv4 entries — drop (continue) on an
			// IPv6/malformed entry BEFORE the append so an invalid string never
			// lands on tc.CIDRRanges (a pre-barrier reader / negative-shift panic
			// guard). COLLECT-ALL: validateCIDRRangeEntry records each bad entry.
			if !validateCIDRRangeEntry("cidrRanges", section, i, str, diags) {
				continue
			}
			tc.CIDRRanges = append(tc.CIDRRanges, str)
		}
	}
	return tc, nil
}

// validateCIDRRangeEntry validates one cidrRanges entry, recording a diagnostic
// (and returning valid=false) for a malformed or non-IPv4 (IPv4-only tool)
// value. COLLECT-ALL (CFG-02): all bad entries in a list are collected; the
// caller MUST drop an invalid entry (continue before append) so an IPv6/
// malformed string never lands on tc.CIDRRanges (preventing the negative-shift
// panic at the trie hot path). The IPv6 gate is mask length, not To4(), so
// IPv4-mapped IPv6 (::ffff:a.b.c.d/120, non-nil To4() but 16-byte mask) is
// rejected while plain IPv4 CIDRs pass. The MSG-02 grammar is preserved verbatim
// ("invalid %s[%d] %q: %w" / "IPv6 not supported (IPv4-only tool) in %s[%d]:
// %q"); the offending value is quoteCapped (untrusted) inside an AddRaw line.
func validateCIDRRangeEntry(field, section string, i int, str string, diags *ConfigDiagnostics) bool {
	_, ipNet, err := net.ParseCIDR(str)
	if err != nil {
		diags.AddRaw(fmt.Sprintf("[%s] invalid %s[%d] %s: %s", section, field, i, quoteCapped(str), err.Error()))
		return false
	}
	if len(ipNet.Mask) != 4 {
		diags.AddRaw(fmt.Sprintf("[%s] IPv6 not supported (IPv4-only tool) in %s[%d]: %s", section, field, i, quoteCapped(str)))
		return false
	}
	return true
}

func parseSlidingTrieConfig(name string, m map[string]any, diags *ConfigDiagnostics) (*SlidingTrieConfig, error) {
	section := "live." + name
	checkUnknownKeys(m, slidingTrieKeys, "["+section+"] sliding-trie", diags)
	uaRegex, epRegex, err := parseRegexFields(m)
	if err != nil {
		return nil, err
	}
	clusterArgSets, clusterHadError, err := parseClusterArgSetsFromTOML(m, section, diags)
	if err != nil {
		return nil, err
	}
	useForJail, useForJailHadError, err := parseUseForJail(m, section, diags)
	if err != nil {
		return nil, err
	}
	stc := &SlidingTrieConfig{
		UserAgentRegex:         uaRegex,
		EndpointRegex:          epRegex,
		ClusterArgSets:         clusterArgSets,
		UseForJail:             useForJail,
		clusterArgSetsHadError: clusterHadError,
		useForJailHadError:     useForJailHadError,
	}
	if clusterHadError {
		stc.UseForJail = nil // belt-and-suspenders (see parseTrieConfig)
	}
	stc.CompileRegexInto(diags)
	// Sliding tries never consume these bounds for filtering; they feed only
	// Validate(LiveMode), so a [live.<n>] bound is parsed (and thus accepted or
	// rejected) identically to a [static.<n>] bound via the shared helper. A live
	// config that previously set a non-RFC3339 startTime/endTime was silently
	// ignored and now fails load at the barrier (deliberate strictness increase,
	// mirroring the cidrRanges validate-and-discard precedent in this function).
	if stc.startTimeRaw, stc.StartTime, stc.StartTimeHasOffset, err = parseTimeBound(m, "startTime"); err != nil {
		return nil, err
	}
	if stc.endTimeRaw, stc.EndTime, stc.EndTimeHasOffset, err = parseTimeBound(m, "endTime"); err != nil {
		return nil, err
	}
	if v, present := m["slidingWindowMaxTime"]; present {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("slidingWindowMaxTime must be a string, got %T", v)
		}
		duration, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("invalid slidingWindowMaxTime %q: %w", s, err)
		}
		stc.SlidingWindowMaxTime = duration
	}
	if v, present := m["slidingWindowMaxSize"]; present {
		n, ok := v.(int64)
		if !ok {
			return nil, fmt.Errorf("slidingWindowMaxSize must be an integer, got %T", v)
		}
		stc.SlidingWindowMaxSize = int(n)
	}
	if v, present := m["sleepBetweenIterations"]; present {
		n, ok := v.(int64)
		if !ok {
			return nil, fmt.Errorf("sleepBetweenIterations must be an integer, got %T", v)
		}
		stc.SleepBetweenIterations = int(n)
	}
	// cidrRanges is accepted (parity with the static trie key surface) but not
	// consumed by sliding tries (SlidingTrieConfig has no CIDRRanges field, so a
	// live config never reaches trie.CountInRange). We still validate-and-discard
	// each entry so IPv6 fails loud at load identically to static mode. NOTE:
	// this is a deliberate strictness increase — a live config that previously
	// set an IPv6 cidrRanges value was tolerated (ignored) and now fails load;
	// IPv4 cidrRanges remain tolerated-and-ignored exactly as before.
	if v, present := m["cidrRanges"]; present {
		arr, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("cidrRanges must be an array of strings, got %T", v)
		}
		for i, item := range arr {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("cidrRanges[%d] must be a string, got %T", i, item)
			}
			// Validate-and-discard (sliding tries do not consume cidrRanges); a
			// bad entry records a diagnostic. COLLECT-ALL: never returns early.
			validateCIDRRangeEntry("cidrRanges", section, i, str, diags)
		}
	}
	return stc, nil
}

// validateUseForJailAlignment enforces that a PRESENT useForJail array lines up
// positionally with clusterArgSets, recording a diagnostic on a mismatch.
// Downstream (cli/api.go, analysis/static.go) indexes argSet[i] against
// useForJail[i], so a present-but-mismatched array silently shifts and disables
// operator-requested jail rules — the landmine the ticket calls out.
//
// GUARD (CFG-02, security): SKIP the check when clusterHadError || jailHadError
// for this trie — EITHER producer dropped a row/element, shortening its slice,
// which would emit a SPURIOUS mismatch. The guard trips on ANY error for the
// trie (not per-row). The barrier already aborts on the producer's diagnostic.
//
// An OMITTED useForJail (len 0) is valid regardless of clusterArgSets length:
// it is the explicit "cluster but never jail" default, an omitted-optional-
// field, not a misalignment.
func validateUseForJailAlignment(section string, clusterArgSets []ClusterArgSet, useForJail []bool, clusterHadError, jailHadError bool, diags *ConfigDiagnostics) {
	if clusterHadError || jailHadError {
		return
	}
	if len(useForJail) == 0 {
		return
	}
	if len(useForJail) != len(clusterArgSets) {
		diags.AddRaw(fmt.Sprintf("[%s] useForJail has %d entries but clusterArgSets has %d; they must match one-to-one (omit useForJail to apply no jail rules)", section, len(useForJail), len(clusterArgSets)))
	}
}

// SetStartTimeBound records a parsed startTime bound plus the original user
// literal on a TrieConfig built outside the TOML parser (static flags mode).
// It keeps the unexported raw carrier populated so Validate's range diagnostic
// echoes the operator's literal (e.g. "2025-12-01") rather than an empty string.
// hasOffset mirrors the TOML path's StartTimeHasOffset semantics.
func (tc *TrieConfig) SetStartTimeBound(t time.Time, hasOffset bool, raw string) {
	tc.StartTime = &t
	tc.StartTimeHasOffset = hasOffset
	tc.startTimeRaw = raw
}

// SetEndTimeBound is the endTime counterpart of SetStartTimeBound.
func (tc *TrieConfig) SetEndTimeBound(t time.Time, hasOffset bool, raw string) {
	tc.EndTime = &t
	tc.EndTimeHasOffset = hasOffset
	tc.endTimeRaw = raw
}

func (c *Config) GetJailFile() string {
	if c.Global != nil && c.Global.JailFile != "" {
		return c.Global.JailFile
	}
	return JailFile
}

func (c *Config) GetBanFile() string {
	if c.Global != nil && c.Global.BanFile != "" {
		return c.Global.BanFile
	}
	return BanFile
}

// GetReadTimeout returns the configured live TCP read timeout, falling back
// to DefaultLiveReadTimeout when unset.
func (c *Config) GetReadTimeout() time.Duration {
	if c.Live != nil && c.Live.ReadTimeout > 0 {
		return c.Live.ReadTimeout
	}
	return DefaultLiveReadTimeout
}

// ValidateLive is a thin shim over validateLiveInto retained for direct callers
// (the live-validation unit tests) that assert the error channel and the "live
// config" terminology. It runs validateLiveInto on a temp accumulator and
// returns the FIRST emitted message as an error; validateLiveInto's emission
// order is deterministic (scalar/live-section checks before the per-window map
// range) so "first" is stable. validateLiveInto is THE single implementation —
// Validate(LiveMode) delegates to it too, so the message grammar never drifts.
func (c *Config) ValidateLive() error {
	d := &ConfigDiagnostics{}
	c.validateLiveInto(d)
	if len(d.msgs) > 0 {
		return fmt.Errorf("%s", d.msgs[0])
	}
	return nil
}

// validateLiveInto records every live-mode required-field / cross-field problem
// into diags and CONTINUES (collect-all). NIL-SAFETY (security): a nil c.Live /
// nil c.Global is REPORTED (required-section diagnostic) and every dependent
// deref is then GUARDED — never deref a nil after reporting. EMISSION ORDER is
// FIXED and deterministic: live-section scalar checks first, global checks next,
// then the per-window map range LAST, so the shim's "first message" stays
// stable. After LoadConfig c.Live/c.Global are non-nil empty structs; a
// hand-built Config may pass nil and is handled here.
func (c *Config) validateLiveInto(diags *ConfigDiagnostics) {
	if c.Live == nil {
		diags.AddRaw("live config section is required")
	} else {
		if c.Live.Port == "" {
			diags.AddRaw("port is required in live config")
		}
		if c.Live.StatsListen != "" {
			if _, _, err := net.SplitHostPort(c.Live.StatsListen); err != nil {
				diags.AddRaw(fmt.Sprintf("invalid statsListen %s (want host:port): %s", quoteCapped(c.Live.StatsListen), err.Error()))
			}
		}
		// topTalkers > 0 without statsListen is accepted but inert.
		if c.Live.TopTalkers < 0 {
			diags.AddRaw(fmt.Sprintf("topTalkers must be >= 0, got %d", c.Live.TopTalkers))
		}
	}

	if c.Global == nil {
		diags.AddRaw("global config section is required for live mode")
	} else {
		if c.Global.JailFile == "" {
			diags.AddRaw("jailFile is required in global config for live mode")
		}
		if c.Global.BanFile == "" {
			diags.AddRaw("banFile is required in global config for live mode")
		}
	}

	if len(c.LiveTries) == 0 {
		diags.AddRaw("at least one sliding window configuration is required in live mode (e.g., [live.window_name])")
	}

	// Per-window required fields. These default to zero values when omitted,
	// which silently produces an inert window: slidingWindowMaxSize=0 makes
	// NewSlidingWindowTrie store maxEntries=0, so eviction trims the window to
	// zero entries every iteration and clustering runs on an empty window.
	// Naming the window keeps the diagnostic actionable. RANGED LAST so the
	// shim's first-message is one of the deterministic scalar checks above.
	for name, win := range c.LiveTries {
		if win == nil {
			continue
		}
		if win.SlidingWindowMaxSize <= 0 {
			diags.AddRaw(fmt.Sprintf("slidingWindowMaxSize must be > 0 in [live.%s]", name))
		}
		if win.SlidingWindowMaxTime <= 0 {
			diags.AddRaw(fmt.Sprintf("slidingWindowMaxTime must be > 0 in [live.%s]", name))
		}
		if len(win.ClusterArgSets) == 0 {
			diags.AddRaw(fmt.Sprintf("at least one clusterArgSets entry is required in [live.%s]", name))
		}
	}
}

// regexGate evaluates one regex filter against value with an optional
// required-literal prefilter. It preserves the exact semantics of the original
// filter: an empty value never matches, and an absent (nil) compiled regex
// imposes no constraint. The prefilter, when present, is a necessary condition
// for a match, so:
//   - if the prefilter rejects, the regex would too -> reject;
//   - if the prefilter is Exact, its acceptance is equivalent to the regex ->
//     accept without running the regex;
//   - otherwise the authoritative regex decides.
func regexGate(compiled *regexp.Regexp, pf *regexprefilter.Prefilter, value string) bool {
	if compiled == nil {
		return true
	}
	if value == "" {
		return false
	}
	if pf != nil {
		if !pf.MightMatch(value) {
			return false
		}
		if pf.Exact() {
			return true
		}
	}
	return compiled.MatchString(value)
}

// ShouldIncludeRequest checks if a request should be included based on regex filters
func (tc *TrieConfig) ShouldIncludeRequest(req ingestor.Request) bool {
	// Apply useragent regex filter (short-circuit on empty UserAgent)
	if !regexGate(tc.userAgentRegexCompiled, tc.userAgentPrefilter, req.UserAgent) {
		return false
	}

	// Apply endpoint regex filter (short-circuit on empty URI)
	if !regexGate(tc.endpointRegexCompiled, tc.endpointPrefilter, req.URI) {
		return false
	}

	return true
}

// ShouldIncludeRequest checks if a request should be included based on regex filters
func (stc *SlidingTrieConfig) ShouldIncludeRequest(req ingestor.Request) bool {
	// Apply useragent regex filter (short-circuit on empty UserAgent)
	if !regexGate(stc.userAgentRegexCompiled, stc.userAgentPrefilter, req.UserAgent) {
		return false
	}

	// Apply endpoint regex filter (short-circuit on empty URI)
	if !regexGate(stc.endpointRegexCompiled, stc.endpointPrefilter, req.URI) {
		return false
	}

	return true
}

// LoadWhitelistCIDRs loads CIDR ranges from whitelist file
func (c *Config) LoadWhitelistCIDRs() ([]string, error) {
	if c.Global == nil || c.Global.Whitelist == "" {
		return nil, nil
	}

	return loadCIDRFile(c.Global.Whitelist)
}

// LoadBlacklistCIDRs loads CIDR ranges from blacklist file
func (c *Config) LoadBlacklistCIDRs() ([]string, error) {
	if c.Global == nil || c.Global.Blacklist == "" {
		return nil, nil
	}

	return loadCIDRFile(c.Global.Blacklist)
}

// compileRegexFields is the single implementation of the regex-compile logic
// shared by the PUBLIC CompileRegex() and the diagnostics-threading
// CompileRegexInto(diags). It returns the first wrapped compile error (the exact
// substrings "invalid useragentRegex pattern: ..." / "invalid endpointRegex
// pattern: ..." that direct callers assert) and, on success, sets the compiled
// regex AND the prefilter — ORDER MATTERS (security, D1-SECURITY): the prefilter
// is built ONLY after a successful Compile, so a compile failure leaves BOTH the
// compiled regex AND the prefilter nil. regexGate(nil,...) returns true, so a
// FAIL-OPEN would admit all traffic — the barrier (which fires when the
// diagnostic is recorded) is the only thing permitted to run between this and
// any ShouldIncludeRequest call. Never set a partial/garbage prefilter.
func (tc *TrieConfig) compileRegexFields() error {
	if tc.UserAgentRegex != "" {
		compiled, err := regexp.Compile(tc.UserAgentRegex)
		if err != nil {
			return fmt.Errorf("invalid useragentRegex pattern: %w", err)
		}
		tc.userAgentRegexCompiled = compiled
		tc.userAgentPrefilter = regexprefilter.Build(tc.UserAgentRegex)
	}
	if tc.EndpointRegex != "" {
		compiled, err := regexp.Compile(tc.EndpointRegex)
		if err != nil {
			return fmt.Errorf("invalid endpointRegex pattern: %w", err)
		}
		tc.endpointRegexCompiled = compiled
		tc.endpointPrefilter = regexprefilter.Build(tc.EndpointRegex)
	}
	return nil
}

// CompileRegex compiles the regex patterns for a TrieConfig, returning the first
// compile error. It is a PUBLIC thin wrapper retained for direct callers
// (config_test.go TestCompileRegex, prefilter_wiring_test.go, cli/live_loop_test.go)
// that assert the error channel; do NOT remove it. Flags/parse paths use
// CompileRegexInto to route the same failure into a diagnostics accumulator.
func (tc *TrieConfig) CompileRegex() error {
	return tc.compileRegexFields()
}

// CompileRegexInto compiles the regex patterns and, on failure, records the
// wrapped error into diags (verbatim, sanitized — the regexp.Compile error text
// is operator/attacker-influenced via the pattern). It NEVER returns an error;
// callers proceed to build the Config and the barrier aborts before any
// ShouldIncludeRequest call. On failure BOTH compiled+prefilter stay nil (see
// compileRegexFields).
func (tc *TrieConfig) CompileRegexInto(diags *ConfigDiagnostics) {
	if err := tc.compileRegexFields(); err != nil {
		diags.AddRaw(err.Error())
	}
}

// CompileRegex compiles the regex patterns for a SlidingTrieConfig (public thin
// wrapper; see TrieConfig.CompileRegex).
func (stc *SlidingTrieConfig) CompileRegex() error {
	return stc.compileRegexFields()
}

func (stc *SlidingTrieConfig) compileRegexFields() error {
	if stc.UserAgentRegex != "" {
		compiled, err := regexp.Compile(stc.UserAgentRegex)
		if err != nil {
			return fmt.Errorf("invalid useragentRegex pattern: %w", err)
		}
		stc.userAgentRegexCompiled = compiled
		stc.userAgentPrefilter = regexprefilter.Build(stc.UserAgentRegex)
	}
	if stc.EndpointRegex != "" {
		compiled, err := regexp.Compile(stc.EndpointRegex)
		if err != nil {
			return fmt.Errorf("invalid endpointRegex pattern: %w", err)
		}
		stc.endpointRegexCompiled = compiled
		stc.endpointPrefilter = regexprefilter.Build(stc.EndpointRegex)
	}
	return nil
}

// CompileRegexInto is the SlidingTrieConfig counterpart (see
// TrieConfig.CompileRegexInto).
func (stc *SlidingTrieConfig) CompileRegexInto(diags *ConfigDiagnostics) {
	if err := stc.compileRegexFields(); err != nil {
		diags.AddRaw(err.Error())
	}
}

// ParseClusterArgSetsFromStrings parses flat string arrays (from CLI flags)
// into ClusterArgSet slices. Each set consists of 4 consecutive values:
// minClusterSize, minDepth, maxDepth, meanSubnetDifference.
func ParseClusterArgSetsFromStrings(args []string) ([]ClusterArgSet, error) {
	if len(args) == 0 {
		return nil, nil
	}
	if len(args)%4 != 0 {
		return nil, fmt.Errorf("invalid clusterArgSets: each set requires 4 values (minClusterSize,minDepth,maxDepth,meanSubnetDifference)")
	}

	sets := make([]ClusterArgSet, 0, len(args)/4)
	for i := 0; i < len(args); i += 4 {
		minClusterSize, err := strconv.ParseFloat(args[i], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid minClusterSize %q: %w", args[i], err)
		}
		minDepth, err := strconv.ParseFloat(args[i+1], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid minDepth %q: %w", args[i+1], err)
		}
		maxDepth, err := strconv.ParseFloat(args[i+2], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid maxDepth %q: %w", args[i+2], err)
		}
		meanSubnetDiff, err := strconv.ParseFloat(args[i+3], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid meanSubnetDifference %q: %w", args[i+3], err)
		}
		if minDepth > maxDepth {
			return nil, fmt.Errorf("clusterArgSets set %d: minDepth (%d) must be <= maxDepth (%d)", i/4, uint32(minDepth), uint32(maxDepth))
		}
		if maxDepth > 32 {
			return nil, fmt.Errorf("clusterArgSets set %d: maxDepth (%d) must be <= 32", i/4, uint32(maxDepth))
		}
		sets = append(sets, ClusterArgSet{
			MinClusterSize:       uint32(minClusterSize),
			MinDepth:             uint32(minDepth),
			MaxDepth:             uint32(maxDepth),
			MeanSubnetDifference: meanSubnetDiff,
		})
	}
	return sets, nil
}

// LoadUserAgentWhitelistPatterns loads User-Agent patterns from whitelist file
func (c *Config) LoadUserAgentWhitelistPatterns() ([]string, error) {
	if c.Global == nil || c.Global.UserAgentWhitelist == "" {
		return nil, nil
	}
	return loadPatternFile(c.Global.UserAgentWhitelist)
}

// LoadUserAgentBlacklistPatterns loads User-Agent patterns from blacklist file
func (c *Config) LoadUserAgentBlacklistPatterns() ([]string, error) {
	if c.Global == nil || c.Global.UserAgentBlacklist == "" {
		return nil, nil
	}
	return loadPatternFile(c.Global.UserAgentBlacklist)
}

// stripCommentLine normalizes one raw line from a pattern/CIDR list file:
// trims surrounding whitespace, drops a full-line comment (empty or leading
// '#'), strips a trailing inline '#...' comment, and re-trims. It returns the
// cleaned token and whether the line carries content (false = skip this line).
func stripCommentLine(raw string) (string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = strings.TrimSpace(line[:i])
		if line == "" {
			return "", false
		}
	}
	return line, true
}

// loadPatternFile loads patterns from a file (for User-Agent whitelist/blacklist)
func loadPatternFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot open %q: %w", filename, err)
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		pattern, ok := stripCommentLine(scanner.Text())
		if !ok {
			continue
		}
		patterns = append(patterns, pattern)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", filename, err)
	}

	return patterns, nil
}

// loadCIDRFile loads and validates CIDR ranges from a file
func loadCIDRFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot open %q: %w", filename, err)
	}
	defer file.Close()

	var cidrs []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()

		// Skip empty/comment lines and strip any trailing inline '#' comment.
		// lineNum tracks physical lines; the cleaned token is echoed (quoted) in
		// diagnostics for operator clarity (ipv4_only_test.go relies on this).
		line, ok := stripCommentLine(raw)
		if !ok {
			continue
		}

		// Validate CIDR format
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR format in %s:%d: %q", filename, lineNum, line)
		}
		// IPv4-only tool: reject IPv6 at the boundary (fail-loud). net.ParseCIDR
		// accepts IPv6, which would otherwise reach the uint32 numeric hot path.
		// Gate on mask length, not To4(): IPv4-mapped IPv6 (::ffff:a.b.c.d/120) has
		// a non-nil To4() but a 16-byte mask; the mask is 4 bytes only for
		// IPv4-notation CIDRs, so len != 4 rejects every IPv6 form.
		if len(ipNet.Mask) != 4 {
			return nil, fmt.Errorf("IPv6 not supported (IPv4-only tool) in %s:%d: %q", filename, lineNum, line)
		}

		cidrs = append(cidrs, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", filename, err)
	}

	return cidrs, nil
}
