package cli

import (
	"fmt"
	"strings"

	"github.com/ChristianF88/flokbn/output"
)

// outputPlain formats the JSON output as human-readable plain text
func outputPlain(jsonOutput *output.JSONOutput) {
	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("                               flokbn Analysis Results\n")
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
		if trieResult.Stats.UAWhitelistExcluded > 0 {
			fmt.Printf("Excluded (UA whitelist): %s\n", output.FormatNumber(trieResult.Stats.UAWhitelistExcluded))
		}
		fmt.Printf("Unique IPs:              %s\n", output.FormatNumber(trieResult.Stats.UniqueIPs))
		fmt.Printf("Trie Build Time:         %d ms\n", trieResult.Stats.InsertTimeMS)

		// Active Filters
		fmt.Printf("Active Filters:          ")
		filters := output.ActiveFilters(trieResult.Parameters, jsonOutput.GlobalFilters)
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
				fmt.Printf("  Set %d: %s\n", j+1, output.FormatClusterParameters(cluster.Parameters))
				fmt.Printf("  Execution Time: %d μs\n", cluster.ExecutionTimeUS)

				if len(cluster.MergedRanges) > 0 {
					fmt.Printf("  Detected Threat Ranges:\n")
					var totalThreats uint32
					for _, threat := range cluster.MergedRanges {
						fmt.Printf("    %-20s  %10s requests  (%6.2f%%)\n",
							threat.CIDR, output.FormatNumber(int(threat.Requests)), threat.Percentage)
						totalThreats += threat.Requests
					}
					// Percent-of-requests, matching the per-range percentages
					// computed during clustering (denominator = inserted
					// requests, not unique IPs).
					totalPercentage := float64(totalThreats) / float64(trieResult.Stats.TotalRequestsAfterFiltering) * 100
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

	// Warnings and Errors. Info messages (e.g. "Heatmap generated ...") are
	// skipped in plain output, so they must not count towards the section
	// either: a run whose only warnings are infos prints no DIAGNOSTICS block
	// and no empty "Warnings:" header.
	var realWarnings []output.Warning
	for _, warning := range jsonOutput.Warnings {
		if warning.Type != "info" {
			realWarnings = append(realWarnings, warning)
		}
	}

	if len(realWarnings) > 0 || len(jsonOutput.Errors) > 0 {
		fmt.Printf("⚠️  DIAGNOSTICS\n")
		fmt.Printf("────────────────────────────────────────────────────────────────────────────────\n")

		if len(realWarnings) > 0 {
			fmt.Printf("Warnings:\n")
			for _, warning := range realWarnings {
				fmt.Printf("  • %s\n", warning.Message)
			}
		}

		if len(jsonOutput.Errors) > 0 {
			fmt.Printf("Errors:\n")
			for _, err := range jsonOutput.Errors {
				fmt.Printf("  • %s\n", err.Message)
			}
		}

		fmt.Printf("\n")
	}

	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
}

// Active-filter rendering lives in output.ActiveFilters, shared with the TUI so
// the two renderers never drift (and so the global whitelists are always
// listed, not just the per-trie TrieParameters).
