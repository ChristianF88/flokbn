package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ChristianF88/flokbn/analysis"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/ingestor"
	"github.com/ChristianF88/flokbn/output"
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
	// THE pre-work barrier (CFG-01/CFG-02). This is the single choke point that
	// TUI, plot, jail/ban, log parse and clustering all cross - placing it here
	// (rather than in the CLI handlers) makes any future non-CLI caller of
	// executeStaticAnalysis inherit the gate; a caller that bypasses this function
	// inherits nothing, so do not add one. CFG-02 folded the logfile-exists /
	// plotPath-dir / regex / cidrRanges / list-file checks into cfg.Validate, so
	// every config diagnostic enumerates here before any side-effecting work.
	if err := barrier(cfg.Validate(config.StaticMode)); err != nil {
		return err
	}

	// Route to TUI if requested
	if outputConfig.TUI {
		return executeTUI(cfg)
	}

	// No heatmap requested: take the IP-only fast path that never materialises
	// the []accesslog.Request slice (the requests would otherwise be discarded).
	if cfg.Static == nil || cfg.Static.PlotPath == "" {
		result, err := analysis.Static(cfg)
		if err != nil {
			// Analysis error dominates exit status; the marshal return here is
			// secondary (the partial result is still surfaced to the user).
			_ = outputResult(result, outputConfig) // Output with errors
			return fmt.Errorf("static analysis: %w", err)
		}
		return outputResult(result, outputConfig)
	}

	// Heatmap requested: keep the full path so we can reuse the parsed requests.
	result, requests, err := analysis.StaticWithRequests(cfg)
	if err != nil {
		// Analysis error dominates exit status; the marshal return here is
		// secondary (the partial result is still surfaced to the user).
		_ = outputResult(result, outputConfig) // Output with errors
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

	return outputResult(result, outputConfig)
}

// executeTUI runs TUI mode - works for both CLI and config file inputs
func executeTUI(cfg *config.Config) error {
	app := tui.NewAppFromConfig(cfg)

	// Tie the analysis goroutine's lifetime to the TUI: cancelling when app.Run
	// returns stops the analysis short-circuiting before its jail/ban-file side
	// effects, and the ctx guards below make the app setters no-ops once the TUI
	// has exited (so a late-finishing analysis never drives a stopped app).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// plotPath heatmap: written by the analysis goroutine, reported after the
	// TUI has exited (see tuiHeatmap).
	var heatmap tuiHeatmap

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

		// Generate the heatmap if plotPath is provided - reuse parsed requests.
		// Done before the results are shown so a failure is part of them.
		heatmap.write(ctx, cfg.Static.PlotPath, requests, multiTrieResult)

		// Set the complete analysis results first
		app.SetAnalysisResults(multiTrieResult)

		// Then set raw requests for visualization
		if requests != nil {
			app.SetRequestData(requests)
		}
	}()

	err := app.Run()

	// The terminal is ours again: stop the analysis and report the heatmap.
	cancel()
	heatmap.report(os.Stderr)

	if err != nil {
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

// executeLiveAnalysis runs live mode analysis - works for both CLI and config file inputs
func executeLiveAnalysis(cfg *config.Config) error {
	// THE pre-work barrier (CFG-01/CFG-02), first statement so it precedes BOTH
	// the ingest bind (NewTCPIngestorWithOptions below) AND the stats bind (newStatsServer):
	// no path reaches either listener when config diagnostics are non-empty.
	// CFG-02 folded the live required-field checks (validateLiveInto) AND the list-file /
	// regex / cidrRanges / IPv6 checks into cfg.Validate(LiveMode), so an
	// unreadable whitelist or an IPv6 cidrRanges now fails BEFORE bind. Only
	// logging.Setup runs before this in the handler (the logger must exist so the
	// barrier can write to stderr; it binds nothing). live flags mode routes a
	// bad regex into cfg.diags, which this pass copies and enumerates.
	if err := barrier(cfg.Validate(config.LiveMode)); err != nil {
		return err
	}

	if len(cfg.LiveTries) == 0 {
		return fmt.Errorf("at least one sliding window is required in live mode (e.g. [live.<name>])")
	}

	logger := slog.Default()

	// The Lumberjack port is unauthenticated: it binds [live] listen
	// (loopback unless configured otherwise), never all interfaces implicitly.
	listenAddr := cfg.GetListenAddr()
	tlsConfig, err := cfg.IngestTLSConfig()
	if err != nil {
		return fmt.Errorf("ingest TLS: %w", err)
	}
	ing, err := ingestor.NewTCPIngestorWithOptions(listenAddr, ingestor.Options{
		LogFormat:   cfg.GetLiveLogFormat(),
		ReadTimeout: cfg.GetReadTimeout(), // read timeout: avoid client disconnects
		TLS:         tlsConfig,
		Logger:      logger,
	})

	if err != nil {
		return fmt.Errorf("creating ingestor: %w", err)
	}
	// Free the bound listener on every early return below (whitelist/blacklist/
	// UA list/jail load failures all return before runLiveLoop reaches Accept,
	// which is where the cancellation watcher's Close lives). Close is
	// idempotent via closeOnce and tolerates server==nil, so this collapses with
	// the watcher's Close on the normal path - no double-close.
	defer ing.Close()

	totalClusterSets := 0
	for _, trie := range cfg.LiveTries {
		totalClusterSets += len(trie.ClusterArgSets)
	}
	logger.Info("starting live loop",
		"version", version.Version,
		"listen", listenAddr,
		"tls", ingestTLSMode(tlsConfig),
		"log_format", ing.LogFormat(),
		"jail_file", cfg.GetJailFile(),
		"ban_file", cfg.GetBanFile(),
		"windows", len(cfg.LiveTries),
		"cluster_sets", totalClusterSets,
	)

	// Mutual TLS is the only authentication the port has; without it an
	// exposed listener deserves a loud line.
	if !isLoopbackHost(cfg.Live.Listen) && ingestTLSMode(tlsConfig) != "mutual" {
		logger.Warn("ingest listener is reachable from other hosts and does not authenticate clients: anyone who can reach it can inject log events and get ranges banned - restrict it with a firewall, bind it to loopback, or require client certificates (tlsClientCA)",
			"listen", listenAddr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on the first SIGINT/SIGTERM, forced exit on the second.
	stop := make(chan os.Signal, 2)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	finished := make(chan struct{})
	defer close(finished)
	go watchShutdownSignals(stop, finished, cancel, logger, os.Exit)

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

// isLoopbackHost reports whether a [live] listen value keeps the listener on
// this machine. Empty means the default (config.DefaultLiveListen).
func isLoopbackHost(host string) bool {
	if host == "" {
		host = config.DefaultLiveListen
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ingestTLSMode names how the ingest listener is protected: "off" (plain
// TCP), "server" (encrypted, any client) or "mutual" (client certificates
// required).
func ingestTLSMode(c *tls.Config) string {
	switch {
	case c == nil:
		return "off"
	case c.ClientAuth == tls.RequireAndVerifyClientCert:
		return "mutual"
	default:
		return "server"
	}
}

// watchShutdownSignals turns the first signal on sig into a graceful shutdown
// (cancel) and the second into an immediate exit. The handler has to outlive
// the first signal: signal.Notify stays registered for the whole shutdown, so
// with nobody reading sig a second Ctrl-C would be swallowed and a stalled
// shutdown could only be ended with SIGKILL. It returns when finished is
// closed (the live loop has returned).
func watchShutdownSignals(sig <-chan os.Signal, finished <-chan struct{}, cancel context.CancelFunc, logger *slog.Logger, exit func(int)) {
	select {
	case <-sig:
	case <-finished:
		return
	}
	logger.Info("received shutdown signal, shutting down (signal again to exit immediately)")
	cancel()

	select {
	case <-sig:
		logger.Error("received second shutdown signal, exiting immediately")
		exit(1)
	case <-finished:
	}
}

// newStatsServerFromConfig binds the stats listener when [live] statsListen
// is set; nil server means the feature is off (zero additional loop cost).
func newStatsServerFromConfig(cfg *config.Config) (*statsServer, error) {
	if cfg.Live == nil || cfg.Live.StatsListen == "" {
		return nil, nil
	}
	return newStatsServer(cfg.Live.StatsListen)
}

// ============================================================================
// OUTPUT FUNCTIONS - Unified output handling (static mode)
// ============================================================================

// outputResult is the unified output function that handles all output formats.
// A JSON marshal failure is reported to stderr AND returned so the caller can
// propagate a non-zero exit: a silent return would otherwise produce no output
// while exiting 0, masking the failure.
func outputResult(jsonOutput *output.JSONOutput, outputConfig OutputConfig) error {
	if outputConfig.Plain {
		outputPlain(jsonOutput)
		return nil
	}

	var jsonBytes []byte
	var err error

	if outputConfig.Compact {
		jsonBytes, err = jsonOutput.ToCompactJSON()
	} else {
		jsonBytes, err = jsonOutput.ToJSON()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot marshal JSON output: %v\n", err)
		return fmt.Errorf("cannot marshal JSON output: %w", err)
	}
	fmt.Println(string(jsonBytes))
	return nil
}
