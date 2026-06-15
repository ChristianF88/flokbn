package output

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestJSONOutput_ToJSON_RoundTrip(t *testing.T) {
	startTime := time.Now()
	out := NewJSONOutput("static", startTime)

	// Populate metadata
	out.Metadata.Version = "2.0.0"

	// Populate general stats
	out.General = General{
		LogFile:       "/var/log/access.log",
		TotalRequests: 1046826,
		UniqueIPs:     52341,
		Parsing: Parsing{
			DurationMS:    762,
			RatePerSecond: 1373322,
			Format:        "%h %l %u %t",
		},
	}

	// Add a trie result with cluster data
	out.Tries = []TrieResult{
		{
			Name: "cli_trie",
			Parameters: TrieParameters{
				CIDRRanges: []string{"14.160.0.0/12"},
			},
			Stats: TrieStats{
				TotalRequestsAfterFiltering: 1046826,
				UniqueIPs:                   52341,
				InsertTimeMS:                316,
				CIDRAnalysis: []CIDRRange{
					{CIDR: "14.160.0.0/12", Requests: 58195, Percentage: 5.56},
				},
			},
			Data: []ClusterResult{
				{
					Parameters: ClusterParameters{
						MinClusterSize:       1000,
						MinDepth:             24,
						MaxDepth:             32,
						MeanSubnetDifference: 0.1,
					},
					ExecutionTimeUS: 95,
					DetectedRanges: []CIDRRange{
						{CIDR: "45.40.50.192/26", Requests: 3083, Percentage: 0.29},
					},
				},
			},
		},
	}

	// Add a CIDR range
	out.CIDRAnalysis.Data = []CIDRRange{
		{CIDR: "10.0.0.0/8", Requests: 12345, Percentage: 1.18},
	}

	// Add a warning
	out.AddWarning("parse_error", "some lines failed to parse", 42)

	// Serialize to JSON
	data, err := out.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error: %v", err)
	}

	// Deserialize back
	var restored JSONOutput
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	// Verify key fields survived the round trip
	if restored.Metadata.AnalysisType != "static" {
		t.Errorf("AnalysisType = %q, want %q", restored.Metadata.AnalysisType, "static")
	}
	if restored.Metadata.Version != "2.0.0" {
		t.Errorf("Version = %q, want %q", restored.Metadata.Version, "2.0.0")
	}
	if restored.General.TotalRequests != 1046826 {
		t.Errorf("TotalRequests = %d, want %d", restored.General.TotalRequests, 1046826)
	}
	if restored.General.LogFile != "/var/log/access.log" {
		t.Errorf("LogFile = %q, want %q", restored.General.LogFile, "/var/log/access.log")
	}
	if restored.General.Parsing.RatePerSecond != 1373322 {
		t.Errorf("RatePerSecond = %d, want %d", restored.General.Parsing.RatePerSecond, 1373322)
	}
	if len(restored.Tries) != 1 {
		t.Fatalf("len(Tries) = %d, want 1", len(restored.Tries))
	}
	if restored.Tries[0].Name != "cli_trie" {
		t.Errorf("Tries[0].Name = %q, want %q", restored.Tries[0].Name, "cli_trie")
	}
	if restored.Tries[0].Stats.UniqueIPs != 52341 {
		t.Errorf("Tries[0].Stats.UniqueIPs = %d, want %d", restored.Tries[0].Stats.UniqueIPs, 52341)
	}
	if len(restored.Tries[0].Data) != 1 {
		t.Fatalf("len(Tries[0].Data) = %d, want 1", len(restored.Tries[0].Data))
	}
	if len(restored.Tries[0].Data[0].DetectedRanges) != 1 {
		t.Fatalf("len(DetectedRanges) = %d, want 1", len(restored.Tries[0].Data[0].DetectedRanges))
	}
	if restored.Tries[0].Data[0].DetectedRanges[0].CIDR != "45.40.50.192/26" {
		t.Errorf("DetectedRanges[0].CIDR = %q, want %q", restored.Tries[0].Data[0].DetectedRanges[0].CIDR, "45.40.50.192/26")
	}
	if restored.Tries[0].Data[0].Parameters.MinClusterSize != 1000 {
		t.Errorf("MinClusterSize = %d, want %d", restored.Tries[0].Data[0].Parameters.MinClusterSize, 1000)
	}
	if len(restored.CIDRAnalysis.Data) != 1 {
		t.Fatalf("len(CIDRAnalysis.Data) = %d, want 1", len(restored.CIDRAnalysis.Data))
	}
	if restored.CIDRAnalysis.Data[0].CIDR != "10.0.0.0/8" {
		t.Errorf("CIDRAnalysis.Data[0].CIDR = %q, want %q", restored.CIDRAnalysis.Data[0].CIDR, "10.0.0.0/8")
	}
	if len(restored.Warnings) != 1 {
		t.Fatalf("len(Warnings) = %d, want 1", len(restored.Warnings))
	}
	if restored.Warnings[0].Type != "parse_error" {
		t.Errorf("Warnings[0].Type = %q, want %q", restored.Warnings[0].Type, "parse_error")
	}
	if restored.Warnings[0].Count != 42 {
		t.Errorf("Warnings[0].Count = %d, want %d", restored.Warnings[0].Count, 42)
	}

	// Also verify compact JSON round-trips
	compact, err := out.ToCompactJSON()
	if err != nil {
		t.Fatalf("ToCompactJSON() error: %v", err)
	}
	var restoredCompact JSONOutput
	if err := json.Unmarshal(compact, &restoredCompact); err != nil {
		t.Fatalf("Unmarshal compact error: %v", err)
	}
	if restoredCompact.General.TotalRequests != 1046826 {
		t.Errorf("compact round-trip TotalRequests = %d, want %d", restoredCompact.General.TotalRequests, 1046826)
	}
}

func TestJSONOutput_AddWarning_Concurrent(t *testing.T) {
	out := NewJSONOutput("static", time.Now())

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			out.AddWarning("concurrent", fmt.Sprintf("warning from goroutine %d", id), id)
		}(i)
	}
	wg.Wait()

	if len(out.Warnings) != goroutines {
		t.Errorf("len(Warnings) = %d, want %d", len(out.Warnings), goroutines)
	}

	// Verify all goroutine IDs are represented
	seen := make(map[int]bool)
	for _, w := range out.Warnings {
		seen[w.Count] = true
	}
	for i := 0; i < goroutines; i++ {
		if !seen[i] {
			t.Errorf("missing warning from goroutine %d", i)
		}
	}
}

func TestJSONOutput_AddError_Concurrent(t *testing.T) {
	out := NewJSONOutput("static", time.Now())

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			out.AddError("concurrent", fmt.Sprintf("error from goroutine %d", id), id)
		}(i)
	}
	wg.Wait()

	if len(out.Errors) != goroutines {
		t.Errorf("len(Errors) = %d, want %d", len(out.Errors), goroutines)
	}

	// Verify all goroutine IDs are represented
	seen := make(map[int]bool)
	for _, e := range out.Errors {
		seen[e.Count] = true
	}
	for i := 0; i < goroutines; i++ {
		if !seen[i] {
			t.Errorf("missing error from goroutine %d", i)
		}
	}
}

func TestFormatNumber(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{999, "999"},
		{1000, "1,000"},
		{1234567, "1,234,567"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.input), func(t *testing.T) {
			got := FormatNumber(tt.input)
			if got != tt.want {
				t.Errorf("FormatNumber(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func BenchmarkFormatNumber(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		FormatNumber(1234567)
	}
}

func BenchmarkToJSON(b *testing.B) {
	out := NewJSONOutput("static", time.Now())
	out.General = General{
		TotalRequests: 1000000,
		UniqueIPs:     50000,
		Parsing:       Parsing{DurationMS: 500, RatePerSecond: 2000000},
	}
	out.Tries = []TrieResult{
		{
			Name: "bench_trie",
			Stats: TrieStats{
				TotalRequestsAfterFiltering: 1000000,
				UniqueIPs:                   50000,
				InsertTimeMS:                200,
			},
			Data: []ClusterResult{
				{
					Parameters: ClusterParameters{MinClusterSize: 1000, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.1},
					DetectedRanges: []CIDRRange{
						{CIDR: "10.0.0.0/24", Requests: 5000, Percentage: 0.5},
						{CIDR: "192.168.1.0/24", Requests: 3000, Percentage: 0.3},
					},
				},
			},
		},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out.ToJSON()
	}
}

func BenchmarkToCompactJSON(b *testing.B) {
	out := NewJSONOutput("static", time.Now())
	out.General = General{
		TotalRequests: 1000000,
		UniqueIPs:     50000,
		Parsing:       Parsing{DurationMS: 500, RatePerSecond: 2000000},
	}
	out.Tries = []TrieResult{
		{
			Name: "bench_trie",
			Stats: TrieStats{
				TotalRequestsAfterFiltering: 1000000,
				UniqueIPs:                   50000,
				InsertTimeMS:                200,
			},
			Data: []ClusterResult{
				{
					Parameters: ClusterParameters{MinClusterSize: 1000, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.1},
					DetectedRanges: []CIDRRange{
						{CIDR: "10.0.0.0/24", Requests: 5000, Percentage: 0.5},
						{CIDR: "192.168.1.0/24", Requests: 3000, Percentage: 0.3},
					},
				},
			},
		},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out.ToCompactJSON()
	}
}

func BenchmarkAddWarning(b *testing.B) {
	out := NewJSONOutput("static", time.Now())
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out.AddWarning("bench", "benchmark warning", 1)
	}
}
