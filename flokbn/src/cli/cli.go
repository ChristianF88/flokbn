package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/iputils"
	"github.com/ChristianF88/flokbn/logging"
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
		Usage: "Log format string (e.g., '%h %^ %^ [%t] \"r\" %s %b %^ \"%u\"')",
		Value: "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\"",
	}
	startTimeFlag = &cli.StringFlag{
		Name:  "startTime",
		Usage: "Start time (formats: YYYY-MM-DD, YYYY-MM-DD HH, or YYYY-MM-DD HH:MM)",
	}
	endTimeFlag = &cli.StringFlag{
		Name:  "endTime",
		Usage: "End time (formats: YYYY-MM-DD, YYYY-MM-DD HH, or YYYY-MM-DD HH:MM)",
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

	for _, flag := range flagsToCheck {
		if c.IsSet(flag) && !allowed[flag] {
			return fmt.Errorf("when using --config, only %v flags are allowed", allowedFlags)
		}
	}
	return nil
}

func validateCIDRRanges(c *cli.Context) error {
	if rangesCidr := c.StringSlice("rangesCidr"); len(rangesCidr) > 0 {
		for _, cidr := range rangesCidr {
			if !iputils.IsValidCidrOrIP(cidr) {
				return fmt.Errorf("invalid CIDR range: %s", cidr)
			}
		}
	}
	return nil
}

func validatePlotPath(plotPath string) error {
	if plotPath != "" {
		plotDir := filepath.Dir(plotPath)
		if plotDir == "." {
			var err error
			plotDir, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("getting working directory: %w", err)
			}
		}
		if _, err := os.Stat(plotDir); os.IsNotExist(err) {
			return fmt.Errorf("plot directory does not exist: %s", plotDir)
		}
	}
	return nil
}

func validateLogFileExists(logfilePath string) error {
	if _, err := os.Stat(logfilePath); os.IsNotExist(err) {
		return fmt.Errorf("logfile does not exist: %s", logfilePath)
	}
	return nil
}

func parseFlexibleTime(input string) (time.Time, error) {
	formats := []string{
		"2006-01-02 15:04", // full datetime
		"2006-01-02 15",    // date + hour
		"2006-01-02",       // just date
	}

	for _, layout := range formats {
		if t, err := time.Parse(layout, input); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid time format: %s", input)
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

// handleLiveConfigMode handles live command when using config file
func handleLiveConfigMode(c *cli.Context, configPath string) error {
	// Validate only allowed flags in config mode
	if err := validateConfigModeFlags(c, []string{"logLevel"}); err != nil {
		return err
	}

	// Load and validate config
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Validate live mode configuration
	if err := cfg.ValidateLive(); err != nil {
		return fmt.Errorf("invalid live configuration: %w", err)
	}

	// Install the process-wide logger; --logLevel overrides [log] level.
	level := cfg.Log.Level
	if c.IsSet("logLevel") {
		level = c.String("logLevel")
	}
	if err := logging.Setup(level, cfg.Log.Format); err != nil {
		return err
	}

	slog.Info("starting live mode", "config", configPath)
	return LiveFromConfig(cfg)
}

// handleLiveFlagsMode handles live command when using CLI flags only.
// It builds a full Config struct and delegates to LiveFromConfig so that
// all features (filtering, whitelist/blacklist, custom clusters) work
// identically whether the user provides a config file or CLI flags.
func handleLiveFlagsMode(c *cli.Context) error {
	if !c.IsSet("port") || !c.IsSet("jailFile") || !c.IsSet("banFile") {
		return fmt.Errorf("port, jailFile, and banFile are required when not using --config")
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

	if err := slidingConfig.CompileRegex(); err != nil {
		return err
	}

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
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Validate logfile exists
	if err := validateLogFileExists(cfg.Static.LogFile); err != nil {
		return err
	}

	// Validate plot path if provided
	if err := validatePlotPath(cfg.Static.PlotPath); err != nil {
		return err
	}

	// Use unified static interface
	return StaticFromConfig(cfg, c.Bool("compact"), c.Bool("plain"), c.Bool("tui"))
}

// handleStaticFlagsMode handles static command when using CLI flags only.
// It builds a full Config struct and delegates to StaticFromConfig so that
// all features (regex filtering, whitelist/blacklist, jail, CIDR ranges)
// work identically whether the user provides a config file or CLI flags.
func handleStaticFlagsMode(c *cli.Context) error {
	if !c.IsSet("logfile") {
		return fmt.Errorf("logfile is required when not using --config")
	}

	if err := validateLogFileExists(c.String("logfile")); err != nil {
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
		Static: &config.StaticConfig{
			LogFile:   c.String("logfile"),
			LogFormat: c.String("logFormat"),
			PlotPath:  c.String("plotPath"),
		},
		StaticTries: make(map[string]*config.TrieConfig),
	}

	trieConfig := &config.TrieConfig{
		UserAgentRegex: c.String("useragentRegex"),
		EndpointRegex:  c.String("endpointRegex"),
		CIDRRanges:     c.StringSlice("rangesCidr"),
	}

	// Compile and validate regex patterns
	if err := trieConfig.CompileRegex(); err != nil {
		return err
	}

	// Parse time arguments
	if start := c.String("startTime"); start != "" {
		st, err := parseFlexibleTime(start)
		if err != nil {
			return fmt.Errorf("error parsing start time: %w", err)
		}
		trieConfig.StartTime = &st
	}
	if end := c.String("endTime"); end != "" {
		et, err := parseFlexibleTime(end)
		if err != nil {
			return fmt.Errorf("error parsing end time: %w", err)
		}
		trieConfig.EndTime = &et
	}

	// Parse cluster arguments
	clusterArgs, err := config.ParseClusterArgSetsFromStrings(c.StringSlice("clusterArgSets"))
	if err != nil {
		return err
	}
	trieConfig.ClusterArgSets = clusterArgs
	// CLI-provided cluster sets default to jailing (parity with live flags
	// mode); TOML configs keep explicit per-set control via useForJail.
	for range clusterArgs {
		trieConfig.UseForJail = append(trieConfig.UseForJail, true)
	}

	// Validate CIDR ranges
	if err := validateCIDRRanges(c); err != nil {
		return err
	}

	// Validate plot path
	if err := validatePlotPath(c.String("plotPath")); err != nil {
		return err
	}

	cfg.StaticTries["cli_trie"] = trieConfig

	return StaticFromConfig(cfg, c.Bool("compact"), c.Bool("plain"), c.Bool("tui"))
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
