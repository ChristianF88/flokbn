package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ChristianF88/flokbn/version"
)

// JSONOutput represents the complete analysis output structure
type JSONOutput struct {
	Metadata              Metadata     `json:"metadata"`
	General               General      `json:"general"`
	Tries                 []TrieResult `json:"tries,omitempty"`
	Clustering            Clustering   `json:"clustering"`
	CIDRAnalysis          CIDRAnalysis `json:"cidr_analysis"`
	Warnings              []Warning    `json:"warnings"`
	Errors                []Error      `json:"errors"`
	UserAgentWhitelistIPs []string     `json:"useragent_whitelist_ips,omitempty"`
	UserAgentBlacklistIPs []string     `json:"useragent_blacklist_ips,omitempty"`
	// GlobalFilters is ALWAYS present in the JSON output. This is a deliberate
	// schema choice: the "global_filters" key is emitted on every run (it is not
	// omitempty — a non-pointer struct cannot be, and we would not want it to be
	// anyway), carrying zero counts when no whitelist is configured. Consumers can
	// therefore rely on the key existing and need not special-case its absence.
	GlobalFilters GlobalFilters `json:"global_filters"`

	// Mutex for thread-safe warning/error appending
	mu sync.Mutex `json:"-"`
}

// GlobalFilters records how many entries each globally-configured whitelist
// holds. These whitelists drop requests from every trie regardless of the
// per-trie TrieParameters, so they must be surfaced as active filters even on a
// baseline trie that has no per-trie filters of its own. Only counts are kept
// here (not the entries themselves) — the renderers report TYPE + COUNT.
//
// Blacklists are intentionally excluded: they do not filter trie membership
// (they only affect the published ban list), so they are not "active filters".
type GlobalFilters struct {
	IPWhitelistCIDRs    int `json:"ip_whitelist_cidrs"`
	UAWhitelistPatterns int `json:"ua_whitelist_patterns"`
}

// Metadata contains information about the analysis run
type Metadata struct {
	GeneratedAt  time.Time `json:"generated_at"`
	AnalysisType string    `json:"analysis_type"`
	Version      string    `json:"version"`
	DurationMS   int64     `json:"duration_ms"`
}

// General contains overall statistics and information
type General struct {
	LogFile       string     `json:"log_file,omitempty"`
	TotalRequests int        `json:"total_requests"`
	UniqueIPs     int        `json:"unique_ips"`
	TimeRange     *TimeRange `json:"time_range,omitempty"`
	Parsing       Parsing    `json:"parsing"`
}

// TimeRange represents the time window of analysis
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Parsing contains parsing performance metrics
type Parsing struct {
	DurationMS    int64  `json:"duration_ms"`
	RatePerSecond int64  `json:"rate_per_second"`
	Format        string `json:"format,omitempty"`
}

// Clustering contains all clustering analysis results
type Clustering struct {
	Metadata ClusteringMetadata `json:"metadata"`
	Data     []ClusterResult    `json:"data"`
}

// ClusteringMetadata describes the clustering section
type ClusteringMetadata struct {
	Description   string `json:"description"`
	TotalClusters int    `json:"total_clusters"`
}

// ClusterResult represents results from one clustering run
type ClusterResult struct {
	Parameters      ClusterParameters `json:"parameters"`
	ExecutionTimeUS int64             `json:"execution_time_us"`
	DetectedRanges  []CIDRRange       `json:"detected_ranges"`
	MergedRanges    []CIDRRange       `json:"merged_ranges"`
}

// TrieResult represents the results from analyzing one trie configuration
type TrieResult struct {
	Name       string          `json:"name"`
	Parameters TrieParameters  `json:"parameters"`
	Stats      TrieStats       `json:"stats"`
	Data       []ClusterResult `json:"data"`
}

// TrieParameters contains the filtering and configuration parameters for a trie
type TrieParameters struct {
	UserAgentRegex *string    `json:"useragent_regex,omitempty"`
	EndpointRegex  *string    `json:"endpoint_regex,omitempty"`
	TimeRange      *TimeRange `json:"time_range,omitempty"`
	CIDRRanges     []string   `json:"cidr_ranges,omitempty"`
	UseForJail     []bool     `json:"use_for_jail,omitempty"`
}

// TrieStats contains statistics about the trie analysis
type TrieStats struct {
	TotalRequestsAfterFiltering int         `json:"total_requests_after_filtering"`
	UniqueIPs                   int         `json:"unique_ips"`
	SkippedInvalidIPs           int         `json:"skipped_invalid_ips,omitempty"`
	UAWhitelistExcluded         int         `json:"ua_whitelist_excluded,omitempty"`
	InsertTimeMS                int64       `json:"insert_time_ms"`
	CIDRAnalysis                []CIDRRange `json:"cidr_analysis,omitempty"`
}

// ClusterParameters contains the clustering algorithm parameters
type ClusterParameters struct {
	MinClusterSize       uint32  `json:"min_cluster_size"`
	MinDepth             uint32  `json:"min_depth"`
	MaxDepth             uint32  `json:"max_depth"`
	MeanSubnetDifference float64 `json:"mean_subnet_difference"`
}

// CIDRRange represents a CIDR range with its metrics
type CIDRRange struct {
	CIDR       string  `json:"cidr"`
	Requests   uint32  `json:"requests"`
	Percentage float64 `json:"percentage"`
}

// CIDRAnalysis contains analysis of specific CIDR ranges
type CIDRAnalysis struct {
	Metadata CIDRAnalysisMetadata `json:"metadata"`
	Data     []CIDRRange          `json:"data"`
}

// CIDRAnalysisMetadata describes the CIDR analysis section
type CIDRAnalysisMetadata struct {
	Description string `json:"description"`
}

// Warning represents a warning message
type Warning struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Count   int    `json:"count,omitempty"`
}

// Error represents an error message
type Error struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Count   int    `json:"count,omitempty"`
}

// NewJSONOutput creates a new JSONOutput with default metadata
func NewJSONOutput(analysisType string, startTime time.Time) *JSONOutput {
	return &JSONOutput{
		Metadata: Metadata{
			GeneratedAt:  time.Now().UTC(),
			AnalysisType: analysisType,
			Version:      version.Version,
			DurationMS:   time.Since(startTime).Milliseconds(),
		},
		Clustering: Clustering{
			Metadata: ClusteringMetadata{
				Description: "CIDR clustering results",
			},
			Data: []ClusterResult{},
		},
		CIDRAnalysis: CIDRAnalysis{
			Metadata: CIDRAnalysisMetadata{
				Description: "Analysis of specific CIDR ranges",
			},
			Data: []CIDRRange{},
		},
		Warnings: []Warning{},
		Errors:   []Error{},
	}
}

// ToJSON converts the output to pretty-printed JSON
func (j *JSONOutput) ToJSON() ([]byte, error) {
	return json.MarshalIndent(j, "", "  ")
}

// ToCompactJSON converts the output to compact JSON
func (j *JSONOutput) ToCompactJSON() ([]byte, error) {
	return json.Marshal(j)
}

// AddWarning adds a warning to the output (thread-safe)
func (j *JSONOutput) AddWarning(warningType, message string, count int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Warnings = append(j.Warnings, Warning{
		Type:    warningType,
		Message: message,
		Count:   count,
	})
}

// AddError adds an error to the output (thread-safe)
func (j *JSONOutput) AddError(errorType, message string, count int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Errors = append(j.Errors, Error{
		Type:    errorType,
		Message: message,
		Count:   count,
	})
}

// LiveCIDR represents a CIDR with its count in live mode (served via /stats)
type LiveCIDR struct {
	CIDR  string `json:"cidr"`
	Count uint32 `json:"count"`
}

// UpdateDuration updates the duration in metadata
func (j *JSONOutput) UpdateDuration(startTime time.Time) {
	j.Metadata.DurationMS = time.Since(startTime).Milliseconds()
}

// ActiveFilters returns the human-readable list of filters that are dropping
// requests from a trie. It is the single source of truth shared by every
// renderer (CLI plain output and the TUI summary) so the two never drift.
//
// The per-trie filters (User-Agent regex, endpoint regex, time range) come from
// params; the global whitelists come from gf. The global whitelist entries are
// appended AFTER the per-trie entries, and only when their count is > 0 — so a
// baseline trie with no per-trie filters still reports the active IP/UA
// whitelists instead of "None". Callers should print "None" only when the
// returned slice is empty (i.e. zero per-trie filters AND both whitelist counts
// are zero).
func ActiveFilters(params TrieParameters, gf GlobalFilters) []string {
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

	// Note: CIDRRanges are not filters - they are analysis targets, so we don't include them.

	// Global whitelists drop requests from every trie; report TYPE + COUNT
	// (never the entries themselves), appended after the per-trie filters.
	if gf.IPWhitelistCIDRs > 0 {
		filters = append(filters, fmt.Sprintf("IP whitelist (%d CIDRs)", gf.IPWhitelistCIDRs))
	}
	if gf.UAWhitelistPatterns > 0 {
		filters = append(filters, fmt.Sprintf("UA whitelist (%d patterns)", gf.UAWhitelistPatterns))
	}

	return filters
}

// FormatNumber adds thousand separators to numbers
func FormatNumber(n int) string {
	str := fmt.Sprintf("%d", n)

	// Strip a leading sign so it is never treated as a digit for grouping;
	// it is re-prepended to the grouped digits below. Without this,
	// FormatNumber(-1000) would produce "-,000" instead of "-1,000".
	var sign string
	if len(str) > 0 && str[0] == '-' {
		sign = "-"
		str = str[1:]
	}

	if len(str) <= 3 {
		return sign + str
	}

	var result strings.Builder
	result.WriteString(sign)
	for i, digit := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result.WriteString(",")
		}
		result.WriteRune(digit)
	}
	return result.String()
}
