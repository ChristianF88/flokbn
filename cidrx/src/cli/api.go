package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ChristianF88/cidrx/analysis"
	"github.com/ChristianF88/cidrx/cidr"
	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/jail"
	"github.com/ChristianF88/cidrx/output"
	"github.com/ChristianF88/cidrx/sliding"
	"github.com/ChristianF88/cidrx/tui"
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
	// Route to TUI if requested
	if outputConfig.TUI {
		return executeTUI(cfg)
	}

	// No heatmap requested: take the IP-only fast path that never materialises
	// the []ingestor.Request slice (the requests would otherwise be discarded).
	if cfg.Static == nil || cfg.Static.PlotPath == "" {
		result, err := analysis.ParallelStaticFromConfigNoRequests(cfg)
		if err != nil {
			outputResult(result, outputConfig) // Output with errors
			return fmt.Errorf("static analysis: %w", err)
		}
		outputResult(result, outputConfig)
		return nil
	}

	// Heatmap requested: keep the full path so we can reuse the parsed requests.
	result, requests, err := analysis.ParallelStaticFromConfigWithRequests(cfg)
	if err != nil {
		outputResult(result, outputConfig) // Output with errors
		return fmt.Errorf("static analysis: %w", err)
	}

	// Generate heatmap if plotPath is provided - reuse parsed requests
	if cfg.Static.PlotPath != "" && requests != nil {
		plotStart := time.Now()
		if err := output.PlotHeatmap(requests, cfg.Static.PlotPath); err != nil {
			result.AddError("heatmap", fmt.Sprintf("failed to generate heatmap: %v", err), 1)
		} else {
			plotDuration := time.Since(plotStart)
			result.AddWarning("info", fmt.Sprintf("Heatmap generated in %v at %s", plotDuration, cfg.Static.PlotPath), 0)
		}
	}

	outputResult(result, outputConfig)
	return nil
}

// executeTUI runs TUI mode - works for both CLI and config file inputs
func executeTUI(cfg *config.Config) error {
	app := tui.NewAppFromConfig(cfg, "")

	// Run the complete analysis first (like non-TUI mode), then pass results to TUI
	go func() {
		// Do the same complete analysis as non-TUI mode
		multiTrieResult, requests, err := analysis.ParallelStaticFromConfigWithRequests(cfg)
		if err != nil {
			// Show error in TUI instead of silent failure
			app.ShowError(fmt.Sprintf("Analysis failed: %v", err))
			return
		}

		// Verify we got results
		if multiTrieResult == nil {
			app.ShowError("Analysis completed but returned no results")
			return
		}

		// Set the complete analysis results first
		app.SetAnalysisResults(multiTrieResult)

		// Then set raw requests for visualization
		if requests != nil {
			app.SetRequestData(requests)
		}
	}()

	if err := app.Run(); err != nil {
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

// slidingWindowInstance holds a sliding window and its associated configuration
type slidingWindowInstance struct {
	name   string
	window *sliding.SlidingWindow
	config *config.SlidingTrieConfig
}

// executeLiveAnalysis runs live mode analysis - works for both CLI and config file inputs
func executeLiveAnalysis(cfg *config.Config) error {
	if len(cfg.LiveTries) == 0 {
		return fmt.Errorf("no LiveTries configurations found")
	}

	ing, err := ingestor.NewTCPIngestor(
		":"+cfg.Live.Port,
		cfg.GetReadTimeout(), // read timeout: avoid client disconnects
	)

	if err != nil {
		return fmt.Errorf("creating ingestor: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	go func() {
		select {
		case <-stop:
			shutdownOutput := output.NewJSONOutput("live", time.Now())
			shutdownOutput.AddWarning("info", "Received shutdown signal...", 0)
			outputJSON(shutdownOutput)
			cancel()
		case <-ctx.Done():
		}
	}()

	return runLiveLoop(ctx, ing, cfg, outputJSON)
}

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

// runLiveLoop is the context-cancellable core of live mode. emit receives
// every JSON output the loop produces (production: outputJSON to stdout).
// Cancelling ctx closes the ingestor, which makes the loop exit cleanly.
func runLiveLoop(ctx context.Context, ing ingestor.Ingestor, cfg *config.Config, emit func(*output.JSONOutput)) error {
	if len(cfg.LiveTries) == 0 {
		return fmt.Errorf("no LiveTries configurations found")
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

	jailInstance, err := jail.FileToJail(cfg.GetJailFile())
	if err != nil {
		return fmt.Errorf("reading jail file: %w", err)
	}

	// Output initial connection status as JSON
	initOutput := output.NewJSONOutput("live", time.Now())
	initOutput.AddWarning("info", "Waiting for Filebeat to connect...", 0)
	emit(initOutput)

	if err := ing.Accept(); err != nil {
		return fmt.Errorf("accepting connection: %w", err)
	}

	// Connection established
	connectedOutput := output.NewJSONOutput("live", time.Now())
	connectedOutput.AddWarning("info", "Filebeat connected", 0)
	emit(connectedOutput)

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

	// Calculate maximum sleep time across all windows
	maxSleepTime := 0
	for _, winInst := range windows {
		if winInst.config.SleepBetweenIterations > maxSleepTime {
			maxSleepTime = winInst.config.SleepBetweenIterations
		}
	}

	// blacklist_applied is emitted once per run, on the first successful
	// ban-file write (static emits it once per analysis).
	blacklistWarned := false

	for {
		loopStart := time.Now()
		jsonOutput := output.NewJSONOutput("live", loopStart)

		batch, err := ing.ReadBatch()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			jsonOutput.AddError("read_batch", fmt.Sprintf("read error: %v", err), 1)
			emit(jsonOutput)
			break
		}

		if len(batch) == 0 {
			if ing.IsClosed() {
				jsonOutput.AddWarning("info", "Ingestor closed. Exiting loop.", 0)
				emit(jsonOutput)
				break
			}
			continue
		}

		// Collect all CIDRs to ban from all sliding windows
		var allMergedCIDRs []*net.IPNet
		var allDetectedCIDRs []output.LiveCIDR
		totalClusterDuration := int64(0)
		totalWindowSize := 0

		// Process each sliding window
		for _, winInst := range windows {
			// Filter batch based on this window's regex filters
			timedIps := make([]sliding.TimedIP, 0, len(batch))
			for _, msg := range batch {
				if msg.Timestamp.IsZero() || msg.IPUint32 == 0 {
					continue
				}

				// Apply regex filtering based on window config
				if !winInst.config.ShouldIncludeRequest(msg) {
					continue
				}

				timedIps = append(timedIps, sliding.TimedIP{
					IP:               msg.GetIPNet(),
					Time:             msg.Timestamp,
					EndpointAllowed:  true,
					UserAgentAllowed: true,
				})
			}

			// Update this specific window
			winInst.window.Update(timedIps)
			totalWindowSize += len(winInst.window.IPQueue)

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

				for _, cidrStr := range cidrs {
					_, ipNet, err := net.ParseCIDR(cidrStr)
					if err != nil {
						jsonOutput.AddWarning("cidr_parse_error", fmt.Sprintf("error parsing CIDR %s: %v", cidrStr, err), 1)
						continue
					}
					cidrIPNets = append(cidrIPNets, ipNet)

					// Use IPNet-native count function for speed
					count := winInst.window.Trie.CountInRangeIPNet(ipNet)
					allDetectedCIDRs = append(allDetectedCIDRs, output.LiveCIDR{
						CIDR:  cidrStr,
						Count: count,
					})
				}

				// Only add to jail if useForJail is true
				if useForJail {
					allMergedCIDRs = append(allMergedCIDRs, cidrIPNets...)
				}
			}
		}

		// Merge all CIDRs collected across configurations
		mergedIPNets := cidr.MergeIPNets(allMergedCIDRs)

		// Convert back to strings for display and jail operations
		var mergedCIDRs []string
		for _, ipNet := range mergedIPNets {
			mergedCIDRs = append(mergedCIDRs, ipNet.String())
		}

		// Apply whitelist filtering before jail update (static parity).
		filteredJailCIDRs := cidr.RemoveWhitelisted(mergedCIDRs, whitelistCIDRs)
		if len(whitelistCIDRs) > 0 {
			if removed := len(mergedCIDRs) - len(filteredJailCIDRs); removed > 0 {
				jsonOutput.AddWarning("whitelist_applied", fmt.Sprintf("Whitelist filtering prevented %d CIDRs from being added to jail", removed), 0)
			}
		}

		if err := jailInstance.Update(filteredJailCIDRs); err != nil {
			jsonOutput.AddWarning("jail_update", fmt.Sprintf("some CIDRs failed during jail update: %v", err), 1)
		}
		if err := jail.JailToFile(jailInstance, cfg.GetJailFile()); err != nil {
			jsonOutput.AddError("jail_save", fmt.Sprintf("failed to save jail: %v", err), 1)
		}

		// Whitelist also shields pre-existing jail entries from the ban file,
		// and manual blacklist entries are always appended (static parity).
		activeBans := jailInstance.ListActiveBans()
		filteredActiveBans := cidr.RemoveWhitelisted(activeBans, whitelistCIDRs)
		if err := jail.WriteBanFileWithBlacklist(cfg.GetBanFile(), filteredActiveBans, blacklistCIDRs); err != nil {
			jsonOutput.AddError("banfile_write", fmt.Sprintf("failed to write ban file: %v", err), 1)
		} else if len(blacklistCIDRs) > 0 && !blacklistWarned {
			blacklistWarned = true
			jsonOutput.AddWarning("blacklist_applied", fmt.Sprintf("Added %d manual blacklist entries to ban file", len(blacklistCIDRs)), 0)
		}

		loopEnd := time.Since(loopStart)

		// Set live stats
		jsonOutput.LiveStats = &output.LiveStats{
			WindowSize:      totalWindowSize,
			ProcessedBatch:  len(batch),
			LoopDuration:    loopEnd.Milliseconds(),
			ClusterDuration: totalClusterDuration / 1000, // Convert to milliseconds
			ActiveBans:      filteredActiveBans,
			DetectedCIDRs:   allDetectedCIDRs,
			MergedCIDRs:     mergedCIDRs,
		}

		jsonOutput.UpdateDuration(loopStart)
		emit(jsonOutput)

		// Sleep using maximum sleep time across all windows
		sleepOrDone(ctx, time.Duration(maxSleepTime)*time.Second)
	}
	return nil
}

// ============================================================================
// OUTPUT FUNCTIONS - Unified output handling
// ============================================================================

// outputJSON outputs in default JSON format (non-compact, non-plain)
func outputJSON(jsonOutput *output.JSONOutput) {
	outputResult(jsonOutput, OutputConfig{Compact: false, Plain: false})
}

// outputResult is the unified output function that handles all output formats
func outputResult(jsonOutput *output.JSONOutput, outputConfig OutputConfig) {
	if outputConfig.Plain {
		outputPlain(jsonOutput)
		return
	}

	var jsonBytes []byte
	var err error

	if outputConfig.Compact {
		jsonBytes, err = jsonOutput.ToCompactJSON()
	} else {
		jsonBytes, err = jsonOutput.ToJSON()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal JSON output: %v\n", err)
		return
	}
	fmt.Println(string(jsonBytes))
}

// outputPlain formats the JSON output as human-readable plain text
func outputPlain(jsonOutput *output.JSONOutput) {
	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("                               cidrx Analysis Results\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n\n")

	// General Information
	fmt.Printf("📊 ANALYSIS OVERVIEW\n")
	fmt.Printf("────────────────────────────────────────────────────────────────────────────────\n")
	fmt.Printf("Log File:        %s\n", jsonOutput.General.LogFile)
	fmt.Printf("Analysis Type:   %s\n", jsonOutput.Metadata.AnalysisType)
	fmt.Printf("Generated:       %s\n", jsonOutput.Metadata.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("Duration:        %d ms\n", jsonOutput.Metadata.DurationMS)
	fmt.Printf("\n")

	// Parsing Performance
	fmt.Printf("⚡ PARSING PERFORMANCE\n")
	fmt.Printf("────────────────────────────────────────────────────────────────────────────────\n")
	fmt.Printf("Total Requests:  %s\n", output.FormatNumber(jsonOutput.General.TotalRequests))
	fmt.Printf("Parse Time:      %d ms\n", jsonOutput.General.Parsing.DurationMS)
	fmt.Printf("Parse Rate:      %s requests/sec\n", output.FormatNumber(int(jsonOutput.General.Parsing.RatePerSecond)))
	fmt.Printf("Log Format:      %s\n", jsonOutput.General.Parsing.Format)
	fmt.Printf("\n")

	// Process each trie
	for i, trieResult := range jsonOutput.Tries {
		fmt.Printf("🎯 TRIE: %s\n", trieResult.Name)
		fmt.Printf("────────────────────────────────────────────────────────────────────────────────\n")

		// Trie Statistics
		fmt.Printf("Requests After Filtering: %s\n", output.FormatNumber(trieResult.Stats.TotalRequestsAfterFiltering))
		fmt.Printf("Unique IPs:              %s\n", output.FormatNumber(trieResult.Stats.UniqueIPs))
		fmt.Printf("Trie Build Time:         %d ms\n", trieResult.Stats.InsertTimeMS)

		// Active Filters
		fmt.Printf("Active Filters:          ")
		filters := getActiveFiltersPlain(trieResult.Parameters)
		if len(filters) > 0 {
			fmt.Printf("%s\n", strings.Join(filters, ", "))
		} else {
			fmt.Printf("None\n")
		}
		fmt.Printf("\n")

		// CIDR Range Analysis
		if len(trieResult.Stats.CIDRAnalysis) > 0 {
			fmt.Printf("📍 CIDR RANGE ANALYSIS\n")
			fmt.Printf("...............................................................................  \n")
			for _, cidr := range trieResult.Stats.CIDRAnalysis {
				fmt.Printf("  %-20s  %10s requests  (%6.2f%%)\n",
					cidr.CIDR, output.FormatNumber(int(cidr.Requests)), cidr.Percentage)
			}
			fmt.Printf("\n")
		}

		// Clustering Results
		if len(trieResult.Data) > 0 {
			fmt.Printf("🔍 CLUSTERING RESULTS (%d sets)\n", len(trieResult.Data))
			fmt.Printf("...............................................................................  \n")

			for j, cluster := range trieResult.Data {
				fmt.Printf("  Set %d: min_size=%d, depth=%d-%d, threshold=%.2f\n",
					j+1, cluster.Parameters.MinClusterSize, cluster.Parameters.MinDepth,
					cluster.Parameters.MaxDepth, cluster.Parameters.MeanSubnetDifference)
				fmt.Printf("  Execution Time: %d μs\n", cluster.ExecutionTimeUS)

				if len(cluster.MergedRanges) > 0 {
					fmt.Printf("  Detected Threat Ranges:\n")
					var totalThreats uint32
					for _, threat := range cluster.MergedRanges {
						fmt.Printf("    %-20s  %10s requests  (%6.2f%%)\n",
							threat.CIDR, output.FormatNumber(int(threat.Requests)), threat.Percentage)
						totalThreats += threat.Requests
					}
					totalPercentage := float64(totalThreats) / float64(trieResult.Stats.UniqueIPs) * 100
					fmt.Printf("    %-20s  %10s requests  (%6.2f%%) [TOTAL]\n",
						"───────────────────", output.FormatNumber(int(totalThreats)), totalPercentage)
				} else {
					fmt.Printf("  No significant threat ranges detected\n")
				}
				fmt.Printf("\n")
			}
		}

		// Add separator between tries
		if i < len(jsonOutput.Tries)-1 {
			fmt.Printf("===============================================================================\n\n")
		}
	}

	// Warnings and Errors
	if len(jsonOutput.Warnings) > 0 || len(jsonOutput.Errors) > 0 {
		fmt.Printf("⚠️  DIAGNOSTICS\n")
		fmt.Printf("────────────────────────────────────────────────────────────────────────────────\n")

		if len(jsonOutput.Warnings) > 0 {
			fmt.Printf("Warnings:\n")
			for _, warning := range jsonOutput.Warnings {
				if warning.Type != "info" { // Skip info messages in plain output
					fmt.Printf("  • %s\n", warning.Message)
				}
			}
		}

		if len(jsonOutput.Errors) > 0 {
			fmt.Printf("Errors:\n")
			for _, err := range jsonOutput.Errors {
				fmt.Printf("  • %s\n", err.Message)
			}
		}

		if len(jsonOutput.Warnings) == 0 && len(jsonOutput.Errors) == 0 {
			fmt.Printf("✅ No issues detected\n")
		}
		fmt.Printf("\n")
	}

	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
}

// getActiveFiltersPlain returns a list of active filter descriptions for plain output
func getActiveFiltersPlain(params output.TrieParameters) []string {
	var filters []string

	if params.UserAgentRegex != nil && *params.UserAgentRegex != "" {
		filters = append(filters, fmt.Sprintf("User-Agent: %s", *params.UserAgentRegex))
	}

	if params.EndpointRegex != nil && *params.EndpointRegex != "" {
		filters = append(filters, fmt.Sprintf("Endpoint: %s", *params.EndpointRegex))
	}

	if params.TimeRange != nil {
		if !params.TimeRange.Start.IsZero() || !params.TimeRange.End.IsZero() {
			timeFilter := "Time: "
			if !params.TimeRange.Start.IsZero() {
				timeFilter += params.TimeRange.Start.Format("2006-01-02 15:04")
			} else {
				timeFilter += "∞"
			}
			timeFilter += " → "
			if !params.TimeRange.End.IsZero() {
				timeFilter += params.TimeRange.End.Format("2006-01-02 15:04")
			} else {
				timeFilter += "∞"
			}
			filters = append(filters, timeFilter)
		}
	}

	return filters
}
