package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ChristianF88/flokbn/config/regexprefilter"
	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/logging"
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

	// Raw values for validation reporting when parsing fails
	StartTimeRaw string `toml:"-"`
	EndTimeRaw   string `toml:"-"`

	// Compiled regex patterns for fast filtering
	userAgentRegexCompiled *regexp.Regexp
	endpointRegexCompiled  *regexp.Regexp

	// Required-literal prefilters screen inputs before the regex runs.
	// nil means no prefilter is available (run the regex directly).
	userAgentPrefilter *regexprefilter.Prefilter
	endpointPrefilter  *regexprefilter.Prefilter
}

type SlidingTrieConfig struct {
	UserAgentRegex         string        `toml:"useragentRegex"`
	EndpointRegex          string        `toml:"endpointRegex"`
	SlidingWindowMaxTime   time.Duration `toml:"slidingWindowMaxTime"`
	SlidingWindowMaxSize   int           `toml:"slidingWindowMaxSize"`
	SleepBetweenIterations int           `toml:"sleepBetweenIterations"`
	ClusterArgSets         []ClusterArgSet
	UseForJail             []bool `toml:"useForJail"`

	// Compiled regex patterns for fast filtering
	userAgentRegexCompiled *regexp.Regexp
	endpointRegexCompiled  *regexp.Regexp

	// Required-literal prefilters screen inputs before the regex runs.
	// nil means no prefilter is available (run the regex directly).
	userAgentPrefilter *regexprefilter.Prefilter
	endpointPrefilter  *regexprefilter.Prefilter
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
// other [live] sub-key is treated as a sliding-trie sub-table. Shared by
// LoadConfig's dispatch and parseLiveConfig's strict unknown-key check.
var liveScalarKeys = map[string]struct{}{
	"port":                   {},
	"readTimeout":            {},
	"statsListen":            {},
	"topTalkers":             {},
	"slidingWindowMaxTime":   {},
	"slidingWindowMaxSize":   {},
	"sleepBetweenIterations": {},
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
	}

	for key, value := range rawConfig {
		switch key {
		case "global":
			if globalMap, ok := value.(map[string]any); ok {
				globalConfig, err := parseGlobalConfig(globalMap)
				if err != nil {
					return nil, fmt.Errorf("parsing global config: %w", err)
				}
				config.Global = globalConfig
			}
		case "static":
			if staticMap, ok := value.(map[string]any); ok {
				staticConfig, err := parseStaticConfig(staticMap)
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
						trieConfig, err := parseTrieConfig(trieMap)
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
				logConfig, err := parseLogConfig(logMap)
				if err != nil {
					return nil, fmt.Errorf("parsing log config: %w", err)
				}
				config.Log = logConfig
			}
		case "live":
			if liveMap, ok := value.(map[string]any); ok {
				liveConfig, err := parseLiveConfig(liveMap)
				if err != nil {
					return nil, fmt.Errorf("parsing live config: %w", err)
				}
				config.Live = liveConfig
				// Parse live tries from nested config. Only the recognized
				// scalar keys (liveScalarKeys — the same set parseLiveConfig
				// checks against) are section fields; everything else is a
				// sliding-trie sub-table. One shared set keeps dispatch and the
				// strict unknown-key check aligned.
				for subKey, subValue := range liveMap {
					if _, isScalar := liveScalarKeys[subKey]; isScalar {
						continue
					}
					if trieMap, ok := subValue.(map[string]any); ok {
						trieConfig, err := parseSlidingTrieConfig(trieMap)
						if err != nil {
							return nil, fmt.Errorf("parsing sliding trie config %q: %w", subKey, err)
						}
						if trieConfig != nil {
							config.LiveTries[subKey] = trieConfig
						}
					}
				}
			}
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
// and unknown/misspelled keys are hard errors at load time (mirroring
// parseLogConfig) so an operator mistake fails loud at startup instead of
// silently falling back to defaults.
func parseGlobalConfig(m map[string]any) (*GlobalConfig, error) {
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
			return nil, fmt.Errorf("unknown key %q in [global] section", key)
		}
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}

// parseStaticConfig parses the [static] section's scalar fields. Trie
// sub-tables (map values) are handled by LoadConfig; only the recognized
// scalar keys are validated here. Wrong-typed scalars are hard errors.
func parseStaticConfig(m map[string]any) (*StaticConfig, error) {
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
			return nil, fmt.Errorf("unknown key %q in [static] section", key)
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
func parseLiveConfig(m map[string]any) (*LiveConfig, error) {
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
			return nil, fmt.Errorf("unknown key %q in [live] section", key)
		}
	}
	return config, nil
}

// parseLogConfig parses the [log] section. Unknown keys are rejected so a
// typo (e.g. "lvl") fails loud instead of silently using defaults, and the
// level/format enums are validated via the logging package (the canonical
// rules the logger itself applies).
func parseLogConfig(m map[string]any) (*LogConfig, error) {
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
			return nil, fmt.Errorf("unknown key %q in [log] section (want level, format)", key)
		}
	}
	if err := logging.Validate(config.Level, config.Format); err != nil {
		return nil, err
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

// checkUnknownKeys returns an error if m contains any key not in allowed,
// naming the offending key and section. Shared by the trie parsers so a
// misspelled key (e.g. useForjail, clusterArgSet) fails loud at load time.
func checkUnknownKeys(m map[string]any, allowed map[string]struct{}, section string) error {
	for key := range m {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown key %q in %s section", key, section)
		}
	}
	return nil
}

// parseClusterArgSetsFromTOML parses cluster argument sets from TOML nested
// arrays. It is fail-loud at config-load time, mirroring the CLI path
// (ParseClusterArgSetsFromStrings): a malformed, under-specified, or
// out-of-range row is a hard error naming the offending row index, never a
// silent drop. Silent drops previously shifted the positional useForJail
// alignment (cli/api.go, analysis/static.go index argSet[i] against
// useForJail[i]) and disabled operator-requested jail rules.
func parseClusterArgSetsFromTOML(m map[string]any) ([]ClusterArgSet, error) {
	raw, present := m["clusterArgSets"]
	if !present {
		return nil, nil
	}
	v, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("clusterArgSets must be an array of [minClusterSize,minDepth,maxDepth,meanSubnetDifference] rows, got %T", raw)
	}
	var sets []ClusterArgSet
	for i, item := range v {
		arr, ok := item.([]any)
		if !ok {
			return nil, fmt.Errorf("clusterArgSets row %d must be an array of 4 numbers, got %T", i, item)
		}
		var argSet []float64
		for _, val := range arr {
			switch f := val.(type) {
			case float64:
				argSet = append(argSet, f)
			case int64:
				argSet = append(argSet, float64(f))
			default:
				return nil, fmt.Errorf("clusterArgSets row %d contains a non-numeric value %v (%T)", i, val, val)
			}
		}
		if len(argSet) != 4 {
			return nil, fmt.Errorf("clusterArgSets row %d requires exactly 4 numeric values (minClusterSize,minDepth,maxDepth,meanSubnetDifference), got %d", i, len(argSet))
		}
		minDepth := uint32(argSet[1])
		maxDepth := uint32(argSet[2])
		// 32 is the IPv4 bit width ceiling. Mirror the CLI fail-loud REJECT
		// (ParseClusterArgSetsFromStrings) so an invalid set never reaches
		// collectCIDRsNode and the positional useForJail alignment is preserved.
		if minDepth > maxDepth {
			return nil, fmt.Errorf("clusterArgSets row %d: minDepth (%d) must be <= maxDepth (%d)", i, minDepth, maxDepth)
		}
		if maxDepth > 32 {
			return nil, fmt.Errorf("clusterArgSets row %d: maxDepth (%d) must be <= 32", i, maxDepth)
		}
		sets = append(sets, ClusterArgSet{
			MinClusterSize:       uint32(argSet[0]),
			MinDepth:             minDepth,
			MaxDepth:             maxDepth,
			MeanSubnetDifference: argSet[3],
		})
	}
	return sets, nil
}

// parseUseForJail parses the useForJail boolean array from a TOML map.
// A present-but-wrong-typed value (non-array, or a non-bool element) is a hard
// error so a malformed array can't silently shrink and misalign with
// clusterArgSets (which is positionally indexed downstream).
func parseUseForJail(m map[string]any) ([]bool, error) {
	raw, present := m["useForJail"]
	if !present {
		return nil, nil
	}
	v, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("useForJail must be an array of booleans, got %T", raw)
	}
	result := make([]bool, 0, len(v))
	for i, item := range v {
		b, ok := item.(bool)
		if !ok {
			return nil, fmt.Errorf("useForJail[%d] must be a boolean, got %T", i, item)
		}
		result = append(result, b)
	}
	return result, nil
}

func parseTrieConfig(m map[string]any) (*TrieConfig, error) {
	if err := checkUnknownKeys(m, trieKeys, "trie"); err != nil {
		return nil, err
	}
	uaRegex, epRegex, err := parseRegexFields(m)
	if err != nil {
		return nil, err
	}
	clusterArgSets, err := parseClusterArgSetsFromTOML(m)
	if err != nil {
		return nil, err
	}
	useForJail, err := parseUseForJail(m)
	if err != nil {
		return nil, err
	}
	if err := validateUseForJailAlignment(clusterArgSets, useForJail); err != nil {
		return nil, err
	}
	tc := &TrieConfig{
		UserAgentRegex: uaRegex,
		EndpointRegex:  epRegex,
		ClusterArgSets: clusterArgSets,
		UseForJail:     useForJail,
	}
	if err := tc.CompileRegex(); err != nil {
		return nil, err
	}
	if v, present := m["startTime"]; present {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("startTime must be a string, got %T", v)
		}
		if s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				tc.StartTime = &t
			} else {
				tc.StartTimeRaw = s
			}
		}
	}
	if v, present := m["endTime"]; present {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("endTime must be a string, got %T", v)
		}
		if s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				tc.EndTime = &t
			} else {
				tc.EndTimeRaw = s
			}
		}
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
			tc.CIDRRanges = append(tc.CIDRRanges, str)
		}
	}
	return tc, nil
}

func parseSlidingTrieConfig(m map[string]any) (*SlidingTrieConfig, error) {
	if err := checkUnknownKeys(m, slidingTrieKeys, "sliding trie"); err != nil {
		return nil, err
	}
	uaRegex, epRegex, err := parseRegexFields(m)
	if err != nil {
		return nil, err
	}
	clusterArgSets, err := parseClusterArgSetsFromTOML(m)
	if err != nil {
		return nil, err
	}
	useForJail, err := parseUseForJail(m)
	if err != nil {
		return nil, err
	}
	if err := validateUseForJailAlignment(clusterArgSets, useForJail); err != nil {
		return nil, err
	}
	stc := &SlidingTrieConfig{
		UserAgentRegex: uaRegex,
		EndpointRegex:  epRegex,
		ClusterArgSets: clusterArgSets,
		UseForJail:     useForJail,
	}
	if err := stc.CompileRegex(); err != nil {
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
	return stc, nil
}

// validateUseForJailAlignment enforces that a PRESENT useForJail array lines up
// positionally with clusterArgSets. Downstream (cli/api.go, analysis/static.go)
// indexes argSet[i] against useForJail[i], so a present-but-mismatched array
// silently shifts and disables operator-requested jail rules — that is the
// landmine the ticket calls out, and it is a hard load error here.
//
// An OMITTED useForJail (len 0) is valid regardless of clusterArgSets length:
// it is the explicit "cluster but never jail" default (every set is treated as
// useForJail=false downstream), an omitted-optional-field, not a misalignment.
// This keeps the OWNER's "don't over-fail on omitted optional fields" rule
// while still catching the genuine length-mismatch bug.
func validateUseForJailAlignment(clusterArgSets []ClusterArgSet, useForJail []bool) error {
	if len(useForJail) == 0 {
		return nil
	}
	if len(useForJail) != len(clusterArgSets) {
		return fmt.Errorf("useForJail has %d entries but clusterArgSets has %d; they must match one-to-one (omit useForJail to apply no jail rules)", len(useForJail), len(clusterArgSets))
	}
	return nil
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

func (c *Config) ValidateLive() error {
	if c.Live == nil {
		return fmt.Errorf("live configuration section is required")
	}

	if c.Live.Port == "" {
		return fmt.Errorf("port is required in live configuration")
	}

	if c.Live.StatsListen != "" {
		if _, _, err := net.SplitHostPort(c.Live.StatsListen); err != nil {
			return fmt.Errorf("invalid statsListen %q (want host:port): %w", c.Live.StatsListen, err)
		}
	}

	// topTalkers > 0 without statsListen is accepted but inert.
	if c.Live.TopTalkers < 0 {
		return fmt.Errorf("topTalkers must be >= 0, got %d", c.Live.TopTalkers)
	}

	// Validate required global fields for live mode
	if c.Global == nil {
		return fmt.Errorf("global configuration section is required for live mode")
	}

	if c.Global.JailFile == "" {
		return fmt.Errorf("jailFile is required in global configuration for live mode")
	}

	if c.Global.BanFile == "" {
		return fmt.Errorf("banFile is required in global configuration for live mode")
	}

	// Validate that at least one LiveTries configuration exists
	if len(c.LiveTries) == 0 {
		return fmt.Errorf("at least one sliding window configuration is required in live mode (e.g., [live.window_name])")
	}

	// Per-window required fields. These default to zero values when omitted,
	// which silently produces an inert window: slidingWindowMaxSize=0 makes
	// NewSlidingWindowTrie store maxEntries=0, so eviction trims the window to
	// zero entries every iteration and clustering runs on an empty window.
	// Fail loud at load instead (filters remain optional per OWNER). Naming the
	// window keeps the diagnostic actionable.
	for name, win := range c.LiveTries {
		if win.SlidingWindowMaxSize <= 0 {
			return fmt.Errorf("slidingWindowMaxSize must be > 0 in [live.%s]", name)
		}
		if win.SlidingWindowMaxTime <= 0 {
			return fmt.Errorf("slidingWindowMaxTime must be > 0 in [live.%s]", name)
		}
		if len(win.ClusterArgSets) == 0 {
			return fmt.Errorf("at least one clusterArgSets entry is required in [live.%s]", name)
		}
	}

	return nil
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

// CompileRegex compiles the regex patterns for a TrieConfig.
// Call this after building a TrieConfig from CLI flags so that
// ShouldIncludeRequest works correctly.
func (tc *TrieConfig) CompileRegex() error {
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

// CompileRegex compiles the regex patterns for a SlidingTrieConfig.
func (stc *SlidingTrieConfig) CompileRegex() error {
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

// ParseClusterArgSetsFromStrings parses flat string arrays (from CLI flags)
// into ClusterArgSet slices. Each set consists of 4 consecutive values:
// minClusterSize, minDepth, maxDepth, meanSubnetDifference.
func ParseClusterArgSetsFromStrings(args []string) ([]ClusterArgSet, error) {
	if len(args) == 0 {
		return nil, nil
	}
	if len(args)%4 != 0 {
		return nil, fmt.Errorf("invalid cluster argument sets: each set requires 4 values (minClusterSize,minDepth,maxDepth,meanSubnetDifference)")
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
			return nil, fmt.Errorf("minDepth (%.0f) must be <= maxDepth (%.0f)", minDepth, maxDepth)
		}
		if maxDepth > 32 {
			return nil, fmt.Errorf("maxDepth (%.0f) must be <= 32", maxDepth)
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
		return nil, fmt.Errorf("failed to open file %s: %w", filename, err)
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
		return nil, fmt.Errorf("error reading file %s: %w", filename, err)
	}

	return patterns, nil
}

// loadCIDRFile loads and validates CIDR ranges from a file
func loadCIDRFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer file.Close()

	var cidrs []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()

		// Skip empty/comment lines and strip any trailing inline '#' comment.
		// lineNum tracks physical lines; the original line text is echoed in
		// diagnostics for operator clarity (ipv4_only_test.go relies on this).
		line, ok := stripCommentLine(raw)
		if !ok {
			continue
		}

		// Validate CIDR format
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR format at line %d in %s: %s", lineNum, filename, strings.TrimSpace(raw))
		}
		// IPv4-only tool: reject IPv6 at the boundary (fail-loud). net.ParseCIDR
		// accepts IPv6, which would otherwise reach the uint32 numeric hot path.
		// Gate on mask length, not To4(): IPv4-mapped IPv6 (::ffff:a.b.c.d/120) has
		// a non-nil To4() but a 16-byte mask; the mask is 4 bytes only for
		// IPv4-notation CIDRs, so len != 4 rejects every IPv6 form.
		if len(ipNet.Mask) != 4 {
			return nil, fmt.Errorf("IPv6 CIDR not supported (IPv4-only tool) at line %d in %s: %s", lineNum, filename, line)
		}

		cidrs = append(cidrs, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", filename, err)
	}

	return cidrs, nil
}
