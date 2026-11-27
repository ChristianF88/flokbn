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
	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/config/regexprefilter"
	"github.com/ChristianF88/flokbn/iputils"
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

// TrieCommon holds what a [static.<name>] trie and a [live.<name>] window have
// in common: the request filters and the cluster-arg sets with their jail
// flags. TrieConfig and SlidingTrieConfig embed it by value, so its fields and
// methods are promoted (tc.UserAgentRegex, tc.ShouldIncludeRequest(req)) and a
// call costs the same as on the outer type. Only a composite literal has to
// name it:
//
//	config.TrieConfig{TrieCommon: config.TrieCommon{UserAgentRegex: "bot"}}
type TrieCommon struct {
	UserAgentRegex string `toml:"useragentRegex"`
	EndpointRegex  string `toml:"endpointRegex"`
	// StartTime and EndTime filter requests in a static trie. A live window
	// parses and validates them the same way but does not apply them (the
	// window is bounded by SlidingWindowMaxTime; see Config.LiveWarnings).
	StartTime      *time.Time `toml:"startTime"`
	EndTime        *time.Time `toml:"endTime"`
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

// TrieConfig is one [static.<name>] trie.
type TrieConfig struct {
	TrieCommon
	CIDRRanges []string `toml:"cidrRanges"`
}

// SlidingTrieConfig is one [live.<name>] window.
type SlidingTrieConfig struct {
	TrieCommon
	SlidingWindowMaxTime   time.Duration `toml:"slidingWindowMaxTime"`
	SlidingWindowMaxSize   int           `toml:"slidingWindowMaxSize"`
	SleepBetweenIterations int           `toml:"sleepBetweenIterations"`

	// ignoredKeys lists the keys present in this [live.<name>] table that are
	// accepted but have no effect in live mode (see Config.LiveWarnings).
	ignoredKeys []string
}

type StaticConfig struct {
	LogFile   string `toml:"logFile"`
	LogFormat string `toml:"logFormat"`
	PlotPath  string `toml:"plotPath"`
}

type LiveConfig struct {
	Port        string        `toml:"port"`
	Listen      string        `toml:"listen"`      // address the Lumberjack listener binds; empty = DefaultLiveListen
	LogFormat   string        `toml:"logFormat"`   // format of each event's message; empty = logparser.DefaultLiveLogFormat
	TLSCert     string        `toml:"tlsCert"`     // PEM certificate of the Lumberjack listener; with tlsKey enables TLS
	TLSKey      string        `toml:"tlsKey"`      // PEM private key for tlsCert
	TLSClientCA string        `toml:"tlsClientCA"` // PEM CA bundle; when set, clients must present a certificate it signed (mTLS)
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

// DefaultLiveListen is the address the Lumberjack listener binds when the
// [live] section (or --listen) does not name one. The port is unauthenticated
// - whoever reaches it can inject log events - so the default is loopback;
// receiving from other hosts is an explicit opt-in (e.g. listen = "0.0.0.0").
const DefaultLiveListen = "127.0.0.1"

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
	"listen":                 {},
	"logFormat":              {},
	"tlsCert":                {},
	"tlsKey":                 {},
	"tlsClientCA":            {},
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
	"listen":      {},
	"logFormat":   {},
	"tlsCert":     {},
	"tlsKey":      {},
	"tlsClientCA": {},
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

// trieKeys are the recognized keys of a [static.<name>] trie sub-table: the
// keys TrieCommon.parse reads, plus cidrRanges.
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
// sub-table: every static trie key plus the per-window sliding parameters.
// startTime/endTime/cidrRanges are accepted (parity with the static trie key
// surface) but not consumed by sliding tries; this matches the prior tolerant
// behavior so a config that set them does not start failing now.
var slidingTrieKeys = withKeys(trieKeys,
	"slidingWindowMaxTime",
	"slidingWindowMaxSize",
	"sleepBetweenIterations",
)

// withKeys returns a copy of base extended by extra.
func withKeys(base map[string]struct{}, extra ...string) map[string]struct{} {
	keys := make(map[string]struct{}, len(base)+len(extra))
	for k := range base {
		keys[k] = struct{}{}
	}
	for _, k := range extra {
		keys[k] = struct{}{}
	}
	return keys
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
	// toml.Decode; a previous `,remain` tag here was dead and misleading -
	// BurntSushi/toml populated neither (two `,remain` fields cannot both win),
	// so a refactor to toml.Decode(data, cfg) would have silently lost every
	// trie. Keep the hand-parsing; do not reintroduce a decode tag.
	StaticTries map[string]*TrieConfig        `toml:"-"`
	LiveTries   map[string]*SlidingTrieConfig `toml:"-"`

	// diags accumulates the parse-phase + flags-handler-injected diagnostics
	// (CFG-02). It is NOT a package global - it is allocated at the top of
	// LoadConfig and threaded by-pointer into every parse* function, and the
	// flags handlers append into it directly. Validate(mode) COPIES these
	// messages (read-only on cfg.diags) into a fresh local accumulator and
	// appends its own validate-phase checks there, so Validate is idempotent and
	// cfg.diags never accumulates across calls. A hand-built Config (flags mode
	// or tests) may leave this nil; ensureDiags allocates lazily.
	diags *ConfigDiagnostics

	// lists keeps the content of the [global] list files after their first
	// read, so one run reads each file once (see lists.go).
	lists listFiles
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
//     messages) into a fresh LOCAL accumulator (read-only on cfg.diags - never
//     appends into it).
//   - It then APPENDS its own validate-phase checks into the LOCAL accumulator
//     only: trie timestamps (CFG-01), the effective logFormat (StaticMode),
//     the configured list files (both modes), and validateLiveInto (LiveMode).
//   - Because it never mutates cfg.diags and every check is deterministic,
//     calling Validate twice yields identical Len() and identical Report().
//
// I/O: Validate is NOT pure - it READS the configured whitelist/blacklist/
// UA-list files (unless this Config already read them: each list file is read
// once per Config and kept, see lists.go), the jail file, and stats the log
// file and plot directory. It remains side-effect-free w.r.t. on-disk state
// (it only reads). It is called EXACTLY ONCE per run, at the barrier seam in
// executeStaticAnalysis / executeLiveAnalysis; the run that follows gets the
// list entries read here without opening the files again.
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

	// Per-table checks: the same for a [static.<name>] trie and a
	// [live.<name>] window.
	c.eachTrie(mode, func(section string, t *TrieCommon) {
		t.validateTimestamps(diags, section)
		t.validateUseForJailAlignment(diags, section)
	})

	switch mode {
	case StaticMode:
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
			} else {
				// A filter needing a field the format never extracts would
				// silently match nothing (or everything); reject it here.
				c.validateFilterFields(diags, StaticMode, effFormat)
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
		// (see the guard in analysis.publishJailAndBans); validate the jail at
		// the barrier only when it will actually be loaded.
		if c.Global != nil && c.Global.JailFile != "" && c.Global.BanFile != "" {
			c.validateJailFile(diags)
		}
	case LiveMode:
		c.validateLiveInto(diags)
		c.validateListFiles(diags)
		// Live always loads the jail (newLiveLoop reads it unconditionally), so
		// validate it at the barrier in every live run.
		c.validateJailFile(diags)
	}
	return diags
}

// eachTrie calls fn for every table of the mode - the [static.<name>] tries or
// the [live.<name>] windows - with the table's section name as diagnostics
// spell it ("static.<name>" / "live.<name>", no brackets) and the part both
// kinds share. Tables are visited in map order.
func (c *Config) eachTrie(mode RunMode, fn func(section string, t *TrieCommon)) {
	switch mode {
	case StaticMode:
		for name, tc := range c.StaticTries {
			if tc != nil {
				fn("static."+name, &tc.TrieCommon)
			}
		}
	case LiveMode:
		for name, stc := range c.LiveTries {
			if stc != nil {
				fn("live."+name, &stc.TrieCommon)
			}
		}
	}
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
// double-count).
//
// The entries read here are kept on the Config (lists.go): the enforcers
// downstream (analysis.loadGlobalLists, the static ban publish, newLiveLoop)
// call the same Load methods and get these entries back, so a run reads each
// list file once and enforces exactly what was validated.
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

// validateJailFile surfaces an unloadable jail (unreadable, invalid JSON, or
// anything else jail.Decode rejects) at the barrier via the SAME loader the
// run uses, so it aborts
// before any work instead of the static path silently swallowing it. A
// missing/empty jail is a valid fresh start and records nothing. It is a load
// error to surface (operator-visible on-disk state), not a panic; the loader
// error already names the path.
func (c *Config) validateJailFile(diags *ConfigDiagnostics) {
	if _, err := jail.Load(c.GetJailFile(), jail.DefaultConfig()); err != nil {
		diags.AddRaw(err.Error())
	}
}

// validateTimestamps runs the (a) startTime-format, (b) endTime-format, and
// (c) endTime<startTime range checks for one table, in that order, with NO early
// return: a single table with BOTH a bad startTime AND a bad endTime yields TWO
// messages. The section is passed WITHOUT brackets (Add/AddRange add them) and
// matches the unknown-key grammar prefix ("static."+name / "live."+name).
func (t *TrieCommon) validateTimestamps(diags *ConfigDiagnostics, section string) {
	// Format: raw captured (non-empty) but never parsed => no accepted layout matched.
	if t.startTimeRaw != "" && t.StartTime == nil {
		diags.Add(section, "startTime", t.startTimeRaw, TimeBoundFormats, nil)
	}
	if t.endTimeRaw != "" && t.EndTime == nil {
		diags.Add(section, "endTime", t.endTimeRaw, TimeBoundFormats, nil)
	}
	// Range: only when both bounds parsed. The offset-equality gate matches
	// makeTimeBounds (URGENT-09): a zone-less wall-clock bound and an
	// offset-bearing instant are not comparable via time.Before, so skip then.
	if t.StartTime != nil && t.EndTime != nil && t.StartTimeHasOffset == t.EndTimeHasOffset && t.EndTime.Before(*t.StartTime) {
		diags.AddRange(section, t.endTimeRaw, t.startTimeRaw)
	}
}

// topLevelSections are the recognized top-level tables, in the order
// checkTopLevelSectionTypes reports them.
var topLevelSections = [...]string{"global", "static", "live", "log"}

// checkTopLevelSectionTypes rejects a recognized top-level section that is not
// a TOML table (`global = "x"`, `[[global]]`). LoadConfig's dispatch only acts
// on table values, so a wrong-typed section would otherwise be dropped whole
// and leave an empty section behind - the same fail-open as a misspelled
// section header, hence the same hard error rather than a diagnostic.
func checkTopLevelSectionTypes(raw map[string]any) error {
	for _, name := range topLevelSections {
		value, present := raw[name]
		if !present {
			continue
		}
		if _, isTable := value.(map[string]any); !isTable {
			return fmt.Errorf("section [%s] must be a table, got %s (write it as a [%s] header followed by key = value lines)",
				name, tomlTypeName(value), name)
		}
	}
	return nil
}

// checkSubTableTypes rejects a trie or window written as an array of tables
// (`[[static.name]]`, `[[live.name]]`). Such an entry decodes to a list, so
// the dispatch in LoadConfig would not parse it as a trie, and the section
// parser would report its name as an unknown key of the parent section. It is
// the same mistake as `[[static]]` one level down and gets the same hard
// error. With several offenders the first by name is reported.
//
// Only an array of tables under a non-scalar key qualifies: any other
// non-table value is a misspelled or misplaced key and stays an unknown-key
// diagnostic, and a recognized scalar key keeps its own type error.
func checkSubTableTypes(raw map[string]any) error {
	for _, parent := range [...]struct {
		name       string
		scalarKeys map[string]struct{}
	}{{"static", staticScalarKeys}, {"live", liveScalarKeys}} {
		section, _ := raw[parent.name].(map[string]any)
		var offenders []string
		for key, value := range section {
			if _, isScalar := parent.scalarKeys[key]; isScalar {
				continue
			}
			if _, isArrayOfTables := value.([]map[string]any); isArrayOfTables {
				offenders = append(offenders, key)
			}
		}
		if len(offenders) > 0 {
			sort.Strings(offenders)
			name := parent.name + "." + offenders[0]
			return fmt.Errorf("section [%s] must be a table, got %s (write it as a [%s] header followed by key = value lines)",
				name, tomlTypeName(section[offenders[0]]), name)
		}
	}
	return nil
}

// tomlTypeName names the TOML type of a decoded value for an error message.
func tomlTypeName(v any) string {
	switch v.(type) {
	case string:
		return "a string"
	case int64:
		return "an integer"
	case float64:
		return "a float"
	case bool:
		return "a boolean"
	case time.Time:
		return "a datetime"
	case []map[string]any:
		return "an array of tables"
	case []any:
		return "an array"
	case map[string]any:
		return "a table"
	default:
		return fmt.Sprintf("%T", v)
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

	if err := checkTopLevelSectionTypes(rawConfig); err != nil {
		return nil, err
	}
	if err := checkSubTableTypes(rawConfig); err != nil {
		return nil, err
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
				// scalar keys (staticScalarKeys - the same set parseStaticConfig
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
			// returned error, NOT a collect-all diagnostic - it loses an ENTIRE
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
		case "listen":
			v, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("listen must be a string, got %T", value)
			}
			config.Listen = v
		case "logFormat":
			v, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("logFormat must be a string, got %T", value)
			}
			config.LogFormat = v
		case "tlsCert", "tlsKey", "tlsClientCA":
			v, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("%s must be a string, got %T", key, value)
			}
			switch key {
			case "tlsCert":
				config.TLSCert = v
			case "tlsKey":
				config.TLSKey = v
			default:
				config.TLSClientCA = v
			}
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
// diagnostic - so len(diags additions)==0 implies every input row survived (no
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
		// Range/integrality rules live in validateClusterArgValues, shared with
		// the CLI path (ParseClusterArgSetsFromStrings), so an invalid set never
		// reaches collectCIDRsNode and the positional useForJail alignment is
		// preserved. One diagnostic per rejected row.
		set, verr := validateClusterArgValues(argSet[0], argSet[1], argSet[2], argSet[3])
		if verr != nil {
			diags.AddRaw(fmt.Sprintf("[%s] clusterArgSets row %d: %s", section, i, verr.Error()))
			hadError = true
			continue
		}
		sets = append(sets, set)
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

// parseTimeBound reads a timestamp bound (startTime/endTime) from a trie TOML
// map. A present-but-non-string value is a hard fail-fast (structural error);
// an empty or absent value yields the zero result, accepted as before. A
// non-empty string is returned as raw and, when ParseTimeBound accepts it, as a
// non-nil time with hasOffset reporting whether it carried an explicit zone
// offset (always true for RFC3339; URGENT-09). The raw literal is returned even
// on parse failure so Validate can echo the operator's text. Shared by both
// trie parsers so the static and sliding bound paths cannot drift.
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
	// ParseTimeBound is shared with the --startTime/--endTime flags, so the
	// TOML keys accept the same syntaxes: RFC3339 (always an explicit offset)
	// and the short zone-less / "±HHMM" forms.
	if parsed, offset, perr := ParseTimeBound(s); perr == nil {
		return s, &parsed, offset, nil
	}
	return s, nil, false, nil
}

// parse reads the keys a [static.<name>] and a [live.<name>] table share into
// t: the two regex filters (compiled here), clusterArgSets, useForJail and the
// two time bounds. It is THE parser of those keys for both tables, so the two
// cannot drift. section is "static.<name>" / "live.<name>". A wrong-TYPED
// value is a hard error; every other problem is recorded in diags and parsing
// continues. cidrRanges is not read here: each table parses it last, after its
// own keys (parseCIDRRanges).
func (t *TrieCommon) parse(section string, m map[string]any, diags *ConfigDiagnostics) error {
	var err error
	if t.UserAgentRegex, t.EndpointRegex, err = parseRegexFields(m); err != nil {
		return err
	}
	if t.ClusterArgSets, t.clusterArgSetsHadError, err = parseClusterArgSetsFromTOML(m, section, diags); err != nil {
		return err
	}
	if t.UseForJail, t.useForJailHadError, err = parseUseForJail(m, section, diags); err != nil {
		return err
	}
	// ANTI-MISALIGNMENT (security): when a clusterArgSets row was dropped, the
	// surviving (shorter) slice must NOT be jailed by a mis-sized useForJail.
	// The barrier always aborts when a clusterArgSets diagnostic is present, so
	// this never reaches analysis - but clear UseForJail belt-and-suspenders so
	// even a hypothetical barrier-bypass cannot apply useForJail[i] to a shifted
	// survivor. The alignment check (in Validate) is skipped when either flag is
	// set, so it never emits a spurious second mismatch.
	if t.clusterArgSetsHadError {
		t.UseForJail = nil
	}
	t.CompileRegexInto(section, diags)
	// A non-empty but unparseable startTime/endTime sets the raw carrier (not
	// the parsed pointer) and is surfaced as a diagnostic at Validate, not here;
	// a wrong-TYPE value stays a hard fail-fast. The raw literal is also captured
	// on success so the range diagnostic echoes the operator's original text.
	if t.startTimeRaw, t.StartTime, t.StartTimeHasOffset, err = parseTimeBound(m, "startTime"); err != nil {
		return err
	}
	if t.endTimeRaw, t.EndTime, t.EndTimeHasOffset, err = parseTimeBound(m, "endTime"); err != nil {
		return err
	}
	return nil
}

// parseCIDRRanges reads the cidrRanges key of a trie table and returns its
// valid entries (a bare IPv4 address as /32). A non-array value or a
// non-string element is a hard error.
//
// SECURITY: ONLY valid IPv4 entries are returned - an IPv6/malformed entry is
// dropped so an invalid string never lands on TrieConfig.CIDRRanges (a
// pre-barrier reader / negative-shift panic guard). COLLECT-ALL:
// validateCIDRRangeEntry records each bad entry and the loop continues.
func parseCIDRRanges(m map[string]any, section string, diags *ConfigDiagnostics) ([]string, error) {
	v, present := m["cidrRanges"]
	if !present {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("cidrRanges must be an array of strings, got %T", v)
	}
	var ranges []string
	for i, item := range arr {
		str, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("cidrRanges[%d] must be a string, got %T", i, item)
		}
		if cidrStr, valid := validateCIDRRangeEntry("cidrRanges", section, i, str, diags); valid {
			ranges = append(ranges, cidrStr)
		}
	}
	return ranges, nil
}

func parseTrieConfig(name string, m map[string]any, diags *ConfigDiagnostics) (*TrieConfig, error) {
	section := "static." + name
	checkUnknownKeys(m, trieKeys, "["+section+"] trie", diags)
	tc := &TrieConfig{}
	if err := tc.TrieCommon.parse(section, m, diags); err != nil {
		return nil, err
	}
	var err error
	if tc.CIDRRanges, err = parseCIDRRanges(m, section, diags); err != nil {
		return nil, err
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
//
// A bare IPv4 address is accepted as a single host and returned as "/32" (the
// same rule as --rangesCidr and the whitelist/blacklist files); the caller
// stores the RETURNED value, never the raw string, so a downstream
// net.ParseCIDR always succeeds. A bare IPv6 address is reported as IPv6.
func validateCIDRRangeEntry(field, section string, i int, str string, diags *ConfigDiagnostics) (cidr string, valid bool) {
	_, ipNet, err := net.ParseCIDR(str)
	if err != nil {
		if normalized, ok := iputils.NormalizeIPv4CIDR(str); ok {
			return normalized, true
		}
		if net.ParseIP(str) != nil {
			diags.AddRaw(fmt.Sprintf("[%s] IPv6 not supported (IPv4-only tool) in %s[%d]: %s", section, field, i, quoteCapped(str)))
			return "", false
		}
		diags.AddRaw(fmt.Sprintf("[%s] invalid %s[%d] %s: %s", section, field, i, quoteCapped(str), err.Error()))
		return "", false
	}
	if len(ipNet.Mask) != 4 {
		diags.AddRaw(fmt.Sprintf("[%s] IPv6 not supported (IPv4-only tool) in %s[%d]: %s", section, field, i, quoteCapped(str)))
		return "", false
	}
	return str, true
}

func parseSlidingTrieConfig(name string, m map[string]any, diags *ConfigDiagnostics) (*SlidingTrieConfig, error) {
	section := "live." + name
	checkUnknownKeys(m, slidingTrieKeys, "["+section+"] sliding-trie", diags)
	stc := &SlidingTrieConfig{
		// Same default as the --sleepBetweenIterations flag; overwritten below
		// when the key is present (an explicit 0 is honored).
		SleepBetweenIterations: DefaultSleepBetweenIterations,
	}
	// Keys that are validated below but never consumed by a sliding trie; the
	// live command warns about each one (Config.LiveWarnings).
	for _, key := range ignoredLiveKeys {
		if _, present := m[key]; present {
			stc.ignoredKeys = append(stc.ignoredKeys, key)
		}
	}
	// Sliding tries never consume the time bounds for filtering; they feed only
	// Validate(LiveMode), so a [live.<n>] bound is accepted or rejected exactly
	// like a [static.<n>] bound.
	if err := stc.TrieCommon.parse(section, m, diags); err != nil {
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
	// live config never reaches trie.CountInRange). The entries are still
	// validated, and then discarded, so IPv6 fails loud at load identically to
	// static mode; IPv4 cidrRanges are tolerated and ignored.
	if _, err := parseCIDRRanges(m, section, diags); err != nil {
		return nil, err
	}
	return stc, nil
}

// validateUseForJailAlignment enforces that a PRESENT useForJail array lines up
// positionally with clusterArgSets, recording a diagnostic on a mismatch.
// Downstream (cli/api.go, analysis/static.go) indexes argSet[i] against
// useForJail[i], so a present-but-mismatched array silently shifts and disables
// operator-requested jail rules - the landmine the ticket calls out.
//
// GUARD (CFG-02, security): SKIP the check when clusterArgSetsHadError ||
// useForJailHadError - EITHER producer dropped a row/element, shortening its slice,
// which would emit a SPURIOUS mismatch. The guard trips on ANY error for the
// trie (not per-row). The barrier already aborts on the producer's diagnostic.
//
// An OMITTED useForJail (len 0) is valid regardless of clusterArgSets length:
// it is the explicit "cluster but never jail" default, an omitted-optional-
// field, not a misalignment.
func (t *TrieCommon) validateUseForJailAlignment(diags *ConfigDiagnostics, section string) {
	if t.clusterArgSetsHadError || t.useForJailHadError {
		return
	}
	if len(t.UseForJail) == 0 {
		return
	}
	if len(t.UseForJail) != len(t.ClusterArgSets) {
		diags.AddRaw(fmt.Sprintf("[%s] useForJail has %d entries but clusterArgSets has %d; they must match one-to-one (omit useForJail to apply no jail rules)", section, len(t.UseForJail), len(t.ClusterArgSets)))
	}
}

// AddCIDRRange appends one range that was given outside a config file (the
// --rangesCidr flag) to CIDRRanges, applying the rules of a TOML cidrRanges
// entry: a bare IPv4 address is stored as /32, and an IPv6 or malformed value
// is not stored but recorded in diags with the same two messages. field and i
// name the input in the message ("rangesCidr", position on the command line);
// section is the trie's section name without brackets.
func (tc *TrieConfig) AddCIDRRange(field, section string, i int, value string, diags *ConfigDiagnostics) {
	if cidrStr, valid := validateCIDRRangeEntry(field, section, i, value, diags); valid {
		tc.CIDRRanges = append(tc.CIDRRanges, cidrStr)
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

// GetListenAddr returns the host:port the Lumberjack listener binds: the
// configured [live] listen address (DefaultLiveListen when unset) joined with
// the port.
func (c *Config) GetListenAddr() string {
	host, port := DefaultLiveListen, ""
	if c.Live != nil {
		if c.Live.Listen != "" {
			host = c.Live.Listen
		}
		port = c.Live.Port
	}
	return net.JoinHostPort(host, port)
}

// GetLiveLogFormat returns the format live mode parses each event's message
// with: the configured [live] logFormat, or logparser.DefaultLiveLogFormat
// (combined log format, client IP in the first field) when unset. This is NOT
// the static default, which reads the client IP from a trailing field.
func (c *Config) GetLiveLogFormat() string {
	if c.Live != nil && c.Live.LogFormat != "" {
		return c.Live.LogFormat
	}
	return logparser.DefaultLiveLogFormat
}

// GetReadTimeout returns the configured live TCP read timeout, falling back
// to DefaultLiveReadTimeout when unset.
func (c *Config) GetReadTimeout() time.Duration {
	if c.Live != nil && c.Live.ReadTimeout > 0 {
		return c.Live.ReadTimeout
	}
	return DefaultLiveReadTimeout
}

// validateLiveInto records every live-mode required-field / cross-field problem
// into diags and CONTINUES (collect-all). NIL-SAFETY (security): a nil c.Live /
// nil c.Global is REPORTED (required-section diagnostic) and every dependent
// deref is then GUARDED - never deref a nil after reporting. EMISSION ORDER is
// FIXED and deterministic: live-section scalar checks first, global checks next,
// then the per-window map range LAST, so the first message is stable. After LoadConfig c.Live/c.Global are non-nil empty structs; a
// hand-built Config may pass nil and is handled here.
func (c *Config) validateLiveInto(diags *ConfigDiagnostics) {
	if c.Live == nil {
		diags.AddRaw("live config section is required")
	} else {
		if c.Live.Port == "" {
			diags.AddRaw("port is required in live config")
		}
		// listen is an address only; the port has its own key. A value that is
		// not an IP literal may be a host name, but never carries a port, a
		// path or whitespace.
		if l := c.Live.Listen; l != "" && net.ParseIP(l) == nil && strings.ContainsAny(l, ":/[] \t") {
			diags.AddRaw(fmt.Sprintf("invalid listen %s (want an IP address or host name without a port, e.g. 127.0.0.1 or 0.0.0.0; the port is set with port)", quoteCapped(l)))
		}
		// Load the listener certificate (and client CA) now, so a missing or
		// mismatched file is reported here and not after the port is bound.
		if _, err := c.IngestTLSConfig(); err != nil {
			diags.AddRaw("invalid ingest TLS settings: " + err.Error())
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
		// logFormat: same check as [static] logFormat, on the effective value
		// (an empty logFormat is valid: the live default is used).
		effFormat := c.GetLiveLogFormat()
		if err := logparser.ValidateFormat(effFormat); err != nil {
			diags.Add("live", "logFormat", c.Live.LogFormat,
				"a valid log format string with exactly one %h", err)
		} else {
			c.validateFilterFields(diags, LiveMode, effFormat)
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
		// 0 is a valid "no pause"; a negative value would silently act like 0
		// (the loop takes the largest value across windows, starting from 0).
		if win.SleepBetweenIterations < 0 {
			diags.AddRaw(fmt.Sprintf("sleepBetweenIterations must be >= 0 in [live.%s], got %d", name, win.SleepBetweenIterations))
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

// ShouldIncludeRequest reports whether a request passes the regex filters. It
// is promoted to TrieConfig and SlidingTrieConfig: the static pipeline calls
// it once per request and trie, live mode once per request and window.
func (t *TrieCommon) ShouldIncludeRequest(req accesslog.Request) bool {
	// Apply useragent regex filter (short-circuit on empty UserAgent)
	if !regexGate(t.userAgentRegexCompiled, t.userAgentPrefilter, req.UserAgent) {
		return false
	}

	// Apply endpoint regex filter (short-circuit on empty URI)
	if !regexGate(t.endpointRegexCompiled, t.endpointPrefilter, req.URI) {
		return false
	}

	return true
}

// LoadWhitelistCIDRs returns the CIDR ranges of the [global] whitelist file
// (nil when none is configured). The file is read on the first call for this
// Config; later calls return the same entries, or the same error (lists.go).
func (c *Config) LoadWhitelistCIDRs() ([]string, error) {
	if c.Global == nil || c.Global.Whitelist == "" {
		return nil, nil
	}
	return c.lists.get(&c.lists.whitelist, c.Global.Whitelist, loadCIDRFile)
}

// LoadBlacklistCIDRs returns the CIDR ranges of the [global] blacklist file,
// read once per Config like LoadWhitelistCIDRs.
func (c *Config) LoadBlacklistCIDRs() ([]string, error) {
	if c.Global == nil || c.Global.Blacklist == "" {
		return nil, nil
	}
	return c.lists.get(&c.lists.blacklist, c.Global.Blacklist, loadCIDRFile)
}

// compileFilterRegex compiles one filter pattern (key is the config key,
// "useragentRegex" or "endpointRegex") together with its prefilter. An empty
// pattern means "no filter" and yields nil, nil, nil. The error text keeps the
// exact substrings "invalid useragentRegex pattern: ..." / "invalid
// endpointRegex pattern: ..." that callers and tests match on.
//
// ORDER MATTERS (security, D1-SECURITY): the prefilter is built ONLY after a
// successful Compile, so a compile failure returns BOTH the compiled regex AND
// the prefilter as nil. regexGate(nil,...) returns true, so a FAIL-OPEN would
// admit all traffic - the barrier (which fires when the diagnostic is recorded)
// is the only thing permitted to run between this and any ShouldIncludeRequest
// call. Never return a partial/garbage prefilter.
func compileFilterRegex(key, pattern string) (*regexp.Regexp, *regexprefilter.Prefilter, error) {
	if pattern == "" {
		return nil, nil, nil
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid %s pattern: %w", key, err)
	}
	return compiled, regexprefilter.Build(pattern), nil
}

// recordRegexErrors routes the per-field compile errors of one trie into diags,
// one line per failed field, prefixed with the section ("static.<name>" /
// "live.<name>", no brackets) so the operator knows WHICH trie to fix. The
// regexp.Compile error text is operator/attacker-influenced via the pattern;
// AddRaw sanitizes the assembled line.
func recordRegexErrors(section string, diags *ConfigDiagnostics, errs ...error) {
	for _, err := range errs {
		if err != nil {
			diags.AddRaw("[" + section + "] " + err.Error())
		}
	}
}

// compileRegexFields compiles both filter patterns INDEPENDENTLY: a bad
// useragentRegex does not stop the endpointRegex from being compiled (and
// reported), so one pass surfaces every bad pattern of the trie.
func (t *TrieCommon) compileRegexFields() (uaErr, epErr error) {
	t.userAgentRegexCompiled, t.userAgentPrefilter, uaErr = compileFilterRegex("useragentRegex", t.UserAgentRegex)
	t.endpointRegexCompiled, t.endpointPrefilter, epErr = compileFilterRegex("endpointRegex", t.EndpointRegex)
	return uaErr, epErr
}

// CompileRegexInto compiles the regex patterns and records every failure into
// diags, naming the section (e.g. "static.t2_bots", "live.window"). It NEVER
// returns an error; callers proceed to build the Config and the barrier aborts
// before any ShouldIncludeRequest call. A failed field leaves BOTH its compiled
// regex and its prefilter nil (see compileFilterRegex).
func (t *TrieCommon) CompileRegexInto(section string, diags *ConfigDiagnostics) {
	uaErr, epErr := t.compileRegexFields()
	recordRegexErrors(section, diags, uaErr, epErr)
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
		// Same range/integrality rules as the TOML path (see
		// validateClusterArgValues).
		set, err := validateClusterArgValues(minClusterSize, minDepth, maxDepth, meanSubnetDiff)
		if err != nil {
			return nil, fmt.Errorf("clusterArgSets set %d: %w", i/4, err)
		}
		sets = append(sets, set)
	}
	return sets, nil
}

// LoadUserAgentWhitelistPatterns returns the entries of the [global]
// userAgentWhitelist file, read once per Config like LoadWhitelistCIDRs.
func (c *Config) LoadUserAgentWhitelistPatterns() ([]string, error) {
	if c.Global == nil || c.Global.UserAgentWhitelist == "" {
		return nil, nil
	}
	return c.lists.get(&c.lists.uaWhitelist, c.Global.UserAgentWhitelist, loadPatternFile)
}

// LoadUserAgentBlacklistPatterns returns the entries of the [global]
// userAgentBlacklist file, read once per Config like LoadWhitelistCIDRs.
func (c *Config) LoadUserAgentBlacklistPatterns() ([]string, error) {
	if c.Global == nil || c.Global.UserAgentBlacklist == "" {
		return nil, nil
	}
	return c.lists.get(&c.lists.uaBlacklist, c.Global.UserAgentBlacklist, loadPatternFile)
}

// stripCommentLine normalizes one raw line from a CIDR list file: trims
// surrounding whitespace, drops a full-line comment (empty or leading '#'),
// strips a trailing inline '#...' comment, and re-trims. It returns the cleaned
// token and whether the line carries content (false = skip this line).
//
// CIDR files only: a CIDR can never contain '#'. User-Agent pattern files use
// patternLine, which keeps an inner '#'.
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

// patternLine normalizes one raw line from a User-Agent pattern file: trims
// surrounding whitespace and drops an empty line or a comment line (first
// non-blank character is '#'). Unlike stripCommentLine it does NOT treat an
// inner '#' as a comment: entries are exact User-Agent strings and real
// User-Agents contain '#' ("Mozilla/5.0 (compatible; Foo #1)"), so cutting at
// it would store a truncated entry that never matches.
func patternLine(raw string) (string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
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
		pattern, ok := patternLine(scanner.Text())
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
			// The list files are documented as "IP/CIDR": a bare IPv4 address
			// is a single host. Store it as /32 so every consumer that calls
			// net.ParseCIDR on these strings (cidr, jail) accepts it.
			if normalized, ok := iputils.NormalizeIPv4CIDR(line); ok {
				cidrs = append(cidrs, normalized)
				continue
			}
			// A bare IPv6 address (incl. IPv4-mapped) is an IPv6 problem, not
			// a format problem.
			if net.ParseIP(line) != nil {
				return nil, fmt.Errorf("IPv6 not supported (IPv4-only tool) in %s:%d: %q", filename, lineNum, line)
			}
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
