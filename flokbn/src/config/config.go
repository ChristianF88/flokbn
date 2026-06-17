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

type Config struct {
	Global      *GlobalConfig                 `toml:"global"`
	Static      *StaticConfig                 `toml:"static"`
	Live        *LiveConfig                   `toml:"live"`
	Log         *LogConfig                    `toml:"log"`
	StaticTries map[string]*TrieConfig        `toml:",remain"`
	LiveTries   map[string]*SlidingTrieConfig `toml:",remain"`
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
				config.Global = parseGlobalConfig(globalMap)
			}
		case "static":
			if staticMap, ok := value.(map[string]any); ok {
				config.Static = parseStaticConfig(staticMap)
				// Parse static tries from nested config
				for subKey, subValue := range staticMap {
					// Skip static configuration fields and only process trie configurations
					if subKey != "logFormat" && subKey != "logFile" && subKey != "plotPath" {
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
				// Parse live tries from nested config
				for subKey, subValue := range liveMap {
					// Skip live configuration fields and only process trie configurations
					if subKey != "port" && subKey != "readTimeout" && subKey != "statsListen" && subKey != "topTalkers" && subKey != "slidingWindowMaxTime" && subKey != "slidingWindowMaxSize" && subKey != "sleepBetweenIterations" {
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

func parseGlobalConfig(m map[string]any) *GlobalConfig {
	config := &GlobalConfig{}
	if v, ok := m["jailFile"].(string); ok {
		config.JailFile = v
	}
	if v, ok := m["banFile"].(string); ok {
		config.BanFile = v
	}
	if v, ok := m["whitelist"].(string); ok {
		config.Whitelist = v
	}
	if v, ok := m["blacklist"].(string); ok {
		config.Blacklist = v
	}
	if v, ok := m["userAgentWhitelist"].(string); ok {
		config.UserAgentWhitelist = v
	}
	if v, ok := m["userAgentBlacklist"].(string); ok {
		config.UserAgentBlacklist = v
	}
	return config
}

func parseStaticConfig(m map[string]any) *StaticConfig {
	config := &StaticConfig{}
	if v, ok := m["logFile"].(string); ok {
		config.LogFile = v
	}
	if v, ok := m["logFormat"].(string); ok {
		config.LogFormat = v
	}
	if v, ok := m["plotPath"].(string); ok {
		config.PlotPath = v
	}
	return config
}

func parseLiveConfig(m map[string]any) (*LiveConfig, error) {
	config := &LiveConfig{}
	if v, ok := m["port"].(string); ok {
		config.Port = v
	}
	if v, ok := m["readTimeout"].(string); ok {
		duration, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid readTimeout %q: %w", v, err)
		}
		config.ReadTimeout = duration
	}
	if v, ok := m["statsListen"].(string); ok {
		config.StatsListen = v
	}
	if v, ok := m["topTalkers"].(int64); ok {
		config.TopTalkers = int(v)
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
func parseRegexFields(m map[string]any) (useragentRegex, endpointRegex string) {
	if v, ok := m["useragentRegex"].(string); ok {
		useragentRegex = v
	}
	if v, ok := m["endpointRegex"].(string); ok {
		endpointRegex = v
	}
	return
}

// parseClusterArgSetsFromTOML parses cluster argument sets from TOML nested arrays.
func parseClusterArgSetsFromTOML(m map[string]any) []ClusterArgSet {
	v, ok := m["clusterArgSets"].([]any)
	if !ok {
		return nil
	}
	var sets []ClusterArgSet
	for _, item := range v {
		arr, ok := item.([]any)
		if !ok {
			continue
		}
		var argSet []float64
		for _, val := range arr {
			switch f := val.(type) {
			case float64:
				argSet = append(argSet, f)
			case int64:
				argSet = append(argSet, float64(f))
			}
		}
		if len(argSet) >= 4 {
			minDepth := uint32(argSet[1])
			maxDepth := uint32(argSet[2])
			// Silently skip invalid sets (existing TOML contract); the 32 ceiling
			// (IPv4 bit width) is enforced here as defense-in-depth so an
			// out-of-range set never reaches collectCIDRsNode. The fail-loud
			// REJECT for CLI/runtime surfaces is handled in
			// ParseClusterArgSetsFromStrings and processClustering.
			if minDepth > maxDepth || maxDepth > 32 {
				continue
			}
			sets = append(sets, ClusterArgSet{
				MinClusterSize:       uint32(argSet[0]),
				MinDepth:             minDepth,
				MaxDepth:             maxDepth,
				MeanSubnetDifference: argSet[3],
			})
		}
	}
	return sets
}

// parseUseForJail parses the useForJail boolean array from a TOML map.
func parseUseForJail(m map[string]any) []bool {
	v, ok := m["useForJail"].([]any)
	if !ok {
		return nil
	}
	var result []bool
	for _, item := range v {
		if b, ok := item.(bool); ok {
			result = append(result, b)
		}
	}
	return result
}

func parseTrieConfig(m map[string]any) (*TrieConfig, error) {
	uaRegex, epRegex := parseRegexFields(m)
	tc := &TrieConfig{
		UserAgentRegex: uaRegex,
		EndpointRegex:  epRegex,
		ClusterArgSets: parseClusterArgSetsFromTOML(m),
		UseForJail:     parseUseForJail(m),
	}
	if err := tc.CompileRegex(); err != nil {
		return nil, err
	}
	if v, ok := m["startTime"].(string); ok && v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			tc.StartTime = &t
		} else {
			tc.StartTimeRaw = v
		}
	}
	if v, ok := m["endTime"].(string); ok && v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			tc.EndTime = &t
		} else {
			tc.EndTimeRaw = v
		}
	}
	if v, ok := m["cidrRanges"].([]any); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				tc.CIDRRanges = append(tc.CIDRRanges, str)
			}
		}
	}
	return tc, nil
}

func parseSlidingTrieConfig(m map[string]any) (*SlidingTrieConfig, error) {
	uaRegex, epRegex := parseRegexFields(m)
	stc := &SlidingTrieConfig{
		UserAgentRegex: uaRegex,
		EndpointRegex:  epRegex,
		ClusterArgSets: parseClusterArgSetsFromTOML(m),
		UseForJail:     parseUseForJail(m),
	}
	if err := stc.CompileRegex(); err != nil {
		return nil, err
	}
	if v, ok := m["slidingWindowMaxTime"].(string); ok {
		duration, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid slidingWindowMaxTime %q: %w", v, err)
		}
		stc.SlidingWindowMaxTime = duration
	}
	if v, ok := m["slidingWindowMaxSize"].(int64); ok {
		stc.SlidingWindowMaxSize = int(v)
	}
	if v, ok := m["sleepBetweenIterations"].(int64); ok {
		stc.SleepBetweenIterations = int(v)
	}
	return stc, nil
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

// loadPatternFile loads patterns from a file (for User-Agent whitelist/blacklist)
func loadPatternFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		patterns = append(patterns, line)
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
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Validate CIDR format
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR format at line %d in %s: %s", lineNum, filename, line)
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
