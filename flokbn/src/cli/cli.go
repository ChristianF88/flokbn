package cli

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/iputils"
	"github.com/ChristianF88/flokbn/logging"
	"github.com/ChristianF88/flokbn/logparser"
	"github.com/ChristianF88/flokbn/version"
	cli "github.com/urfave/cli/v2"
)

// parseDate attempts to parse the build date
func parseDate(d string) time.Time {
	t, err := time.Parse(time.RFC3339, d)
	if err != nil {
		return time.Now()
	}
	return t
}

// Shared flag definitions to eliminate duplication
var (
	// Configuration flags
	configFlag = &cli.StringFlag{
		Name:  "config",
		Usage: "Path to configuration file (mutually exclusive with other flags)",
	}

	// Filtering flags
	useragentRegexFlag = &cli.StringFlag{
		Name:  "useragentRegex",
		Usage: "Filter requests by user agent regex pattern (e.g., '.*bot.*')",
	}
	endpointRegexFlag = &cli.StringFlag{
		Name:  "endpointRegex",
		Usage: "Filter requests by endpoint regex pattern (e.g., '/api/.*')",
	}
	rangesCidrFlag = &cli.StringSliceFlag{
		Name:  "rangesCidr",
		Usage: "Provide one or more CIDR ranges to check how many requests are in these range(s).",
	}

	// Output flags
	plotPathFlag = &cli.StringFlag{
		Name:  "plotPath",
		Usage: "Path where to save the heatmap file (e.g., '/path/to/heatmap.html'). If not provided, no plot will be generated.",
	}
	compactFlag = &cli.BoolFlag{
		Name:  "compact",
		Usage: "Output compact JSON (no pretty printing)",
		Value: false,
	}
	plainFlag = &cli.BoolFlag{
		Name:  "plain",
		Usage: "Output plain text format for easy readability",
		Value: false,
	}

	// Jail and ban management flags
	jailFileFlag = &cli.StringFlag{
		Name:  "jailFile",
		Usage: "Path to jail file for ban persistence (e.g., '/tmp/jail.json')",
	}
	banFileFlag = &cli.StringFlag{
		Name:  "banFile",
		Usage: "Path to ban file output (e.g., '/tmp/ban.txt')",
	}

	// Whitelist and blacklist flags
	whitelistFlag = &cli.StringFlag{
		Name:  "whitelist",
		Usage: "Path to IP/CIDR whitelist file (IPs that are never banned)",
	}
	blacklistFlag = &cli.StringFlag{
		Name:  "blacklist",
		Usage: "Path to IP/CIDR blacklist file (IPs that are always banned)",
	}
	userAgentWhitelistFlag = &cli.StringFlag{
		Name:  "userAgentWhitelist",
		Usage: "Path to User-Agent whitelist file (User-Agent patterns that whitelist IPs)",
	}
	userAgentBlacklistFlag = &cli.StringFlag{
		Name:  "userAgentBlacklist",
		Usage: "Path to User-Agent blacklist file (User-Agent patterns that blacklist IPs)",
	}

	// Live-specific flags
	portFlag = &cli.StringFlag{
		Name:  "port",
		Usage: "Port to listen on",
	}
	logLevelFlag = &cli.StringFlag{
		Name:  "logLevel",
		Usage: "Log verbosity (debug, info, warn, error); overrides the [log] level from the config file",
	}
	slidingWindowMaxTimeFlag = &cli.DurationFlag{
		Name:  "slidingWindowMaxTime",
		Usage: "Maximum time duration for sliding window",
		Value: 2 * time.Hour,
	}
	slidingWindowMaxSizeFlag = &cli.IntFlag{
		Name:  "slidingWindowMaxSize",
		Usage: "Maximum number of requests in sliding window",
		Value: 100000,
	}
	sleepBetweenIterationsFlag = &cli.IntFlag{
		Name:  "sleepBetweenIterations",
		Usage: "Sleep duration between iterations in seconds",
		Value: 10,
	}
	clusterArgSetFlag = &cli.StringSliceFlag{
		Name:  "clusterArgSet",
		Usage: "Cluster argument sets (multiple can be passed): minClusterSize,minDepth,maxDepth,meanSubnetDifference",
	}

	// Static-specific flags
	logfileFlag = &cli.StringFlag{
		Name:  "logfile",
		Usage: "Path to the log file",
	}
	logFormatFlag = &cli.StringFlag{
		Name:  "logFormat",
		Usage: "Log format string (e.g., '%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\"')",
		Value: logparser.DefaultLogFormat,
	}
	startTimeFlag = &cli.StringFlag{
		Name:  "startTime",
		Usage: "Start time. Zone-less (e.g. '2025-07-06 06:00') matches a log line's local clock regardless of its offset; add an offset (e.g. '2025-07-06 06:00 +0100') to compare as a true instant. Formats: YYYY-MM-DD, YYYY-MM-DD HH, YYYY-MM-DD HH:MM, optionally + ' ±HHMM'",
	}
	endTimeFlag = &cli.StringFlag{
		Name:  "endTime",
		Usage: "End time. Zone-less (e.g. '2025-07-06 06:00') matches a log line's local clock regardless of its offset; add an offset (e.g. '2025-07-06 06:00 +0100') to compare as a true instant. Formats: YYYY-MM-DD, YYYY-MM-DD HH, YYYY-MM-DD HH:MM, optionally + ' ±HHMM'",
	}
	clusterArgSetsFlag = &cli.StringSliceFlag{
		Name:  "clusterArgSets",
		Usage: "Cluster argument sets: minClusterSize,minDepth,maxDepth,meanSubnetDifference;...",
	}
	tuiFlag = &cli.BoolFlag{
		Name:  "tui",
		Usage: "Launch TUI (Terminal User Interface) mode",
		Value: false,
	}
)

// Shared validation functions
func validateConfigModeFlags(c *cli.Context, allowedFlags []string) error {
	// Create a map for quick lookup of allowed flags
	allowed := make(map[string]bool)
	for _, flag := range allowedFlags {
		allowed[flag] = true
	}

	// Check all possible flags
	flagsToCheck := []string{
		"port", "jailFile", "banFile", "slidingWindowMaxTime", "slidingWindowMaxSize",
		"sleepBetweenIterations", "clusterArgSet", "useragentRegex", "endpointRegex",
		"rangesCidr", "plotPath", "whitelist", "blacklist", "userAgentWhitelist",
		"userAgentBlacklist", "logfile", "logFormat", "startTime", "endTime",
		"clusterArgSets", "tui", "compact", "plain", "logLevel",
	}

	// Accumulate every disallowed flag the user actually set (deterministic
	// order: flagsToCheck is a fixed slice) so the message names the offenders
	// AND lists the allowed set, instead of leaking a raw Go slice.
	var offenders []string
	for _, flag := range flagsToCheck {
		if c.IsSet(flag) && !allowed[flag] {
			offenders = append(offenders, flag)
		}
	}
	if len(offenders) > 0 {
		return fmt.Errorf("--config cannot be combined with %s; with --config only these flags are allowed: %s",
			joinFlags(offenders), joinFlags(allowedFlags))
	}
	return nil
}

// joinFlags renders flag names as a comma-separated list of quoted --flag
// tokens (e.g. `"--tui", "--compact"`), so validation errors name flags in the
// house location grammar rather than leaking a raw Go slice via %v.
func joinFlags(names []string) string {
	if len(names) == 0 {
		return "(none)"
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", "--"+n)
	}
	return strings.Join(quoted, ", ")
}

// CFG-02 moved the static logFile-exists, plotPath-dir-exists and --rangesCidr
// checks out of dedicated validators here: the file/dir stats now run in
// config.Validate and --rangesCidr routes into cfg.diags, so all of them
// enumerate at the single barrier instead of short-circuiting before it.

// parseFlexibleTime parses a CLI --startTime/--endTime bound. It returns the
// parsed time and whether the bound carried an EXPLICIT timezone offset
// (URGENT-09). Zone-less bounds (no offset layout matched) are compared
// wall-clock / zone-agnostically against log lines; offset-bearing bounds are
// compared as a true instant. Offset layouts are tried first so a trailing
// "-0700" is not mis-parsed by a zone-less layout.
func parseFlexibleTime(input string) (t time.Time, hasOffset bool, err error) {
	offsetFormats := []string{
		"2006-01-02 15:04 -0700", // full datetime + offset
		"2006-01-02 15 -0700",    // date + hour + offset
		"2006-01-02 -0700",       // date + offset
	}
	for _, layout := range offsetFormats {
		if parsed, perr := time.Parse(layout, input); perr == nil {
			return parsed, true, nil
		}
	}

	zonelessFormats := []string{
		"2006-01-02 15:04", // full datetime
		"2006-01-02 15",    // date + hour
		"2006-01-02",       // just date
	}
	for _, layout := range zonelessFormats {
		if parsed, perr := time.Parse(layout, input); perr == nil {
			return parsed, false, nil
		}
	}

	return time.Time{}, false, fmt.Errorf("invalid time format %q (want YYYY-MM-DD, \"YYYY-MM-DD HH\", or \"YYYY-MM-DD HH:MM\", each optionally with \" ±HHMM\")", input)
}

// Command handler functions to reduce deep nesting

// handleLiveCommand processes the live command with proper separation of concerns
func handleLiveCommand(c *cli.Context) error {
	configPath := c.String("config")
	if configPath != "" {
		return handleLiveConfigMode(c, configPath)
	}
	return handleLiveFlagsMode(c)
}

// setupLoggerTolerant installs the process-wide logger before the barrier (the
// barrier needs slog to write its report) WITHOUT failing on a bad [log] enum.
// A bad [log] level/format is already a collect-all diagnostic (parseLogConfig),
// so it must enumerate at the barrier with everything else; returning
// logging.Setup's hard error here would short-circuit and hide it. On a bad
// pair we fall back to the defaults (info/text), which always validate.
func setupLoggerTolerant(level, format string) {
	if err := logging.Setup(level, format); err != nil {
		_ = logging.Setup("", "")
	}
}

// handleLiveConfigMode handles live command when using config file
func handleLiveConfigMode(c *cli.Context, configPath string) error {
	// Validate only allowed flags in config mode
	if err := validateConfigModeFlags(c, []string{"logLevel"}); err != nil {
		return err
	}

	// Load and validate config
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("cannot load config %q: %w", configPath, err)
	}

	// CFG-02: the live required-field checks (ValidateLive) and the [log]
	// level/format enum are folded into config.Validate(LiveMode) / parseLogConfig,
	// so they enumerate at the barrier (first statement of executeLiveAnalysis)
	// before any port/stats bind. The logger install below binds nothing and stays
	// before the barrier, but is tolerant of a bad [log] enum so that enum
	// enumerates with everything else (see setupLoggerTolerant).
	//
	// --logLevel is a direct CLI input with no diagnostic path, so a typo'd flag
	// stays a hard return here; when set it overrides the [log] level.
	level := cfg.Log.Level
	if c.IsSet("logLevel") {
		level = c.String("logLevel")
		if _, err := logging.ParseLevel(level); err != nil {
			return err
		}
	}
	setupLoggerTolerant(level, cfg.Log.Format)

	slog.Info("starting live mode", "config", configPath)
	return LiveFromConfig(cfg)
}

// handleLiveFlagsMode handles live command when using CLI flags only.
// It builds a full Config struct and delegates to LiveFromConfig so that
// all features (filtering, whitelist/blacklist, custom clusters) work
// identically whether the user provides a config file or CLI flags.
func handleLiveFlagsMode(c *cli.Context) error {
	if !c.IsSet("port") || !c.IsSet("jailFile") || !c.IsSet("banFile") {
		return fmt.Errorf("--port, --jailFile, and --banFile are required when not using --config")
	}

	// Install the process-wide logger (no config file: defaults + --logLevel).
	if err := logging.Setup(c.String("logLevel"), ""); err != nil {
		return err
	}

	cfg := &config.Config{
		Global: &config.GlobalConfig{
			JailFile:           c.String("jailFile"),
			BanFile:            c.String("banFile"),
			Whitelist:          c.String("whitelist"),
			Blacklist:          c.String("blacklist"),
			UserAgentWhitelist: c.String("userAgentWhitelist"),
			UserAgentBlacklist: c.String("userAgentBlacklist"),
		},
		Live: &config.LiveConfig{
			Port: c.String("port"),
		},
		LiveTries: make(map[string]*config.SlidingTrieConfig),
	}

	slidingConfig := &config.SlidingTrieConfig{
		UserAgentRegex:         c.String("useragentRegex"),
		EndpointRegex:          c.String("endpointRegex"),
		SlidingWindowMaxTime:   c.Duration("slidingWindowMaxTime"),
		SlidingWindowMaxSize:   c.Int("slidingWindowMaxSize"),
		SleepBetweenIterations: c.Int("sleepBetweenIterations"),
	}

	// A bad --useragentRegex/--endpointRegex routes into the persistent cfg.diags
	// (not a throwaway, or a dropped regex error becomes a fail-open no-op filter
	// that admits all traffic), so it enumerates with static flags at the barrier
	// in executeLiveAnalysis before any port/stats bind.
	slidingConfig.CompileRegexInto(cfg.Diagnostics())

	// clusterArgSets arity stays a hard return (parity with static flags mode).
	clusterArgs, err := config.ParseClusterArgSetsFromStrings(c.StringSlice("clusterArgSet"))
	if err != nil {
		return err
	}
	if len(clusterArgs) == 0 {
		// Default cluster config when none provided
		clusterArgs = []config.ClusterArgSet{{
			MinClusterSize: 1000, MinDepth: 30, MaxDepth: 32, MeanSubnetDifference: 0.2,
		}}
		slidingConfig.UseForJail = []bool{true}
	} else {
		for range clusterArgs {
			slidingConfig.UseForJail = append(slidingConfig.UseForJail, true)
		}
	}
	slidingConfig.ClusterArgSets = clusterArgs

	cfg.LiveTries["cli_default"] = slidingConfig
	return LiveFromConfig(cfg)
}

// handleStaticCommand processes the static command with proper separation of concerns
func handleStaticCommand(c *cli.Context) error {
	configPath := c.String("config")
	if configPath != "" {
		return handleStaticConfigMode(c, configPath)
	}
	return handleStaticFlagsMode(c)
}

// handleStaticConfigMode handles static command when using config file
func handleStaticConfigMode(c *cli.Context, configPath string) error {
	// Validate only allowed flags in config mode
	if err := validateConfigModeFlags(c, []string{"tui", "compact", "plain"}); err != nil {
		return err
	}

	// Load and validate config
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("cannot load config %q: %w", configPath, err)
	}

	// CFG-02: the logfile-exists and plotPath-dir-exists checks moved into
	// config.Validate(StaticMode), so they now ENUMERATE at the single barrier
	// alongside any other config diagnostic (e.g. a bad startTime) instead of a
	// stat short-circuit winning before it. The barrier runs as the first
	// statement of executeStaticAnalysis.
	//
	// The empty-logFile "required" case is recorded here (not in Validate) so it
	// enumerates at the barrier too; Validate stays free of a logFile-required
	// rule that the trie-fragment unit tests (which drive it without a logFile)
	// would trip on.
	if cfg.Static == nil || cfg.Static.LogFile == "" {
		cfg.Diagnostics().AddRaw("[static] logFile is required")
	}

	return StaticFromConfig(cfg, c.Bool("compact"), c.Bool("plain"), c.Bool("tui"))
}

// handleStaticFlagsMode handles static command when using CLI flags only.
// It builds a full Config struct and delegates to StaticFromConfig so that
// all features (regex filtering, whitelist/blacklist, jail, CIDR ranges)
// work identically whether the user provides a config file or CLI flags.
func handleStaticFlagsMode(c *cli.Context) error {
	// An unset --logfile is a hard return here (before the config is built); the
	// exists-on-disk stat migrates to a diagnostic (config.Validate, via
	// Static.LogFile). Config mode's empty-logFile case is handled separately in
	// handleStaticConfigMode.
	if !c.IsSet("logfile") {
		return fmt.Errorf("--logfile is required when not using --config")
	}

	cfg := &config.Config{
		Global: &config.GlobalConfig{
			JailFile:           c.String("jailFile"),
			BanFile:            c.String("banFile"),
			Whitelist:          c.String("whitelist"),
			Blacklist:          c.String("blacklist"),
			UserAgentWhitelist: c.String("userAgentWhitelist"),
			UserAgentBlacklist: c.String("userAgentBlacklist"),
		},
		Static: &config.StaticConfig{
			LogFile:   c.String("logfile"),
			LogFormat: c.String("logFormat"),
			PlotPath:  c.String("plotPath"),
		},
		StaticTries: make(map[string]*config.TrieConfig),
	}
	// The persistent diagnostics accumulator that config.Validate copies; the
	// regex/cidrRanges failures below route here (never a throwaway, or a dropped
	// regex error becomes a fail-open no-op filter that admits all traffic).
	diags := cfg.Diagnostics()

	trieConfig := &config.TrieConfig{
		UserAgentRegex: c.String("useragentRegex"),
		EndpointRegex:  c.String("endpointRegex"),
	}

	// A bad --useragentRegex/--endpointRegex routes into cfg.diags; the barrier
	// (in executeStaticAnalysis) enumerates and aborts before analysis. On failure
	// both compiled+prefilter stay nil; analysis never runs.
	trieConfig.CompileRegexInto(diags)

	// Validate --rangesCidr into cfg.diags, storing ONLY valid IPv4 entries on the
	// trie (drop IPv6/malformed before append — never store a bad entry, parity
	// with the TOML cidrRanges path).
	for i, cidrStr := range c.StringSlice("rangesCidr") {
		if !iputils.IsValidCidrOrIP(cidrStr) {
			diags.AddRaw(fmt.Sprintf("[static.cli_trie] invalid rangesCidr[%d] %s", i, strconv.Quote(cidrStr)))
			continue
		}
		trieConfig.CIDRRanges = append(trieConfig.CIDRRanges, cidrStr)
	}

	// A malformed --startTime/--endTime hard-errors here (parseFlexibleTime); the
	// parsed bound is recorded WITH its original literal so the CFG-01 range
	// diagnostic (endTime<startTime) can echo the user's text. The barrier fires
	// the range check downstream when both bounds are zone-equal (both flexible
	// flags are zone-less => offset-equal).
	if start := c.String("startTime"); start != "" {
		st, hasOffset, err := parseFlexibleTime(start)
		if err != nil {
			return fmt.Errorf("parsing --startTime: %w", err)
		}
		trieConfig.SetStartTimeBound(st, hasOffset, start)
	}
	if end := c.String("endTime"); end != "" {
		et, hasOffset, err := parseFlexibleTime(end)
		if err != nil {
			return fmt.Errorf("parsing --endTime: %w", err)
		}
		trieConfig.SetEndTimeBound(et, hasOffset, end)
	}

	// clusterArgSets arity stays a hard return (keeps its direct-call tests green;
	// a deliberate deviation from full barrier parity).
	clusterArgs, err := config.ParseClusterArgSetsFromStrings(c.StringSlice("clusterArgSets"))
	if err != nil {
		return err
	}
	if len(clusterArgs) == 0 {
		// Default cluster config when none provided (parity with live flags mode).
		clusterArgs = []config.ClusterArgSet{{
			MinClusterSize: 1000, MinDepth: 30, MaxDepth: 32, MeanSubnetDifference: 0.2,
		}}
		trieConfig.UseForJail = []bool{true}
	} else {
		// CLI-provided cluster sets default to jailing (parity with live flags
		// mode); TOML configs keep explicit per-set control via useForJail.
		for range clusterArgs {
			trieConfig.UseForJail = append(trieConfig.UseForJail, true)
		}
	}
	trieConfig.ClusterArgSets = clusterArgs

	cfg.StaticTries["cli_trie"] = trieConfig

	// logfile-exists and plotPath-dir-exists are validated in config.Validate
	// (Static.LogFile / Static.PlotPath) and enumerate at the barrier.
	return StaticFromConfig(cfg, c.Bool("compact"), c.Bool("plain"), c.Bool("tui"))
}

func init() {
	// Surface the build commit (and date) alongside the version. The default
	// urfave/cli printer only prints App.Version, so override it to also show
	// version.Commit (set via GoReleaser ldflags) and the build date.
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("flokbn version %s\ncommit: %s\nbuilt: %s\n",
			version.Version, version.Commit, version.Date)
	}
}

var App = &cli.App{
	Name:     "flokbn",
	Usage:    "Cluster IPs either in live mode or from static logs",
	Version:  version.Version,
	Compiled: parseDate(version.Date),
	Commands: []*cli.Command{
		{
			Name:  "live",
			Usage: "Run clustering on live incoming data",
			Flags: []cli.Flag{
				// Configuration
				configFlag,
				// Live-specific flags
				portFlag,
				logLevelFlag,
				slidingWindowMaxTimeFlag,
				slidingWindowMaxSizeFlag,
				sleepBetweenIterationsFlag,
				clusterArgSetFlag,
				// Filtering flags
				useragentRegexFlag,
				endpointRegexFlag,
				// Jail and ban management
				jailFileFlag,
				banFileFlag,
				// Whitelist and blacklist
				whitelistFlag,
				blacklistFlag,
				userAgentWhitelistFlag,
				userAgentBlacklistFlag,
			},
			Action: handleLiveCommand,
		},
		{
			Name:  "static",
			Usage: "Run clustering from a log file",
			Flags: []cli.Flag{
				// Configuration
				configFlag,
				// Static-specific flags
				logfileFlag,
				logFormatFlag,
				startTimeFlag,
				endTimeFlag,
				clusterArgSetsFlag,
				tuiFlag,
				// Filtering flags
				useragentRegexFlag,
				endpointRegexFlag,
				rangesCidrFlag,
				// Output flags
				plotPathFlag,
				compactFlag,
				plainFlag,
				// Jail and ban management
				jailFileFlag,
				banFileFlag,
				// Whitelist and blacklist
				whitelistFlag,
				blacklistFlag,
				userAgentWhitelistFlag,
				userAgentBlacklistFlag,
			},
			Action: handleStaticCommand,
		},
		generateCommand,
	},
}
