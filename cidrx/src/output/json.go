package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// JSONOutput represents the complete analysis output structure
type JSONOutput struct {
	Metadata              Metadata     `json:"metadata"`
	General               General      `json:"general"`
	Tries                 []TrieResult `json:"tries,omitempty"`
	Clustering            Clustering   `json:"clustering,omitempty"`
	CIDRAnalysis          CIDRAnalysis `json:"cidr_analysis,omitempty"`
	Warnings              []Warning    `json:"warnings"`
	Errors                []Error      `json:"errors"`
	UserAgentWhitelistIPs []string     `json:"useragent_whitelist_ips,omitempty"`
	UserAgentBlacklistIPs []string     `json:"useragent_blacklist_ips,omitempty"`

	// Mutex for thread-safe warning/error appending
	mu sync.Mutex `json:"-"`
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
			Version:      "1.0.0",
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

// FormatNumber adds thousand separators to numbers
func FormatNumber(n int) string {
	str := fmt.Sprintf("%d", n)
	if len(str) <= 3 {
		return str
	}

	var result strings.Builder
	for i, digit := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result.WriteString(",")
		}
		result.WriteRune(digit)
	}
	return result.String()
}
