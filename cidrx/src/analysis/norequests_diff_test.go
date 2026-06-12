package analysis

import (
	"reflect"
	"sort"
	"testing"

	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/output"
	"github.com/ChristianF88/cidrx/testutil"
)

// normalizeRanges returns a sorted copy of CIDR ranges keyed by CIDR string so
// comparisons are order-independent (range/cluster ordering can be
// nondeterministic across the two pipelines).
func normalizeRanges(ranges []output.CIDRRange) []output.CIDRRange {
	out := make([]output.CIDRRange, len(ranges))
	copy(out, ranges)
	sort.Slice(out, func(i, j int) bool {
		if out[i].CIDR != out[j].CIDR {
			return out[i].CIDR < out[j].CIDR
		}
		return out[i].Requests < out[j].Requests
	})
	return out
}

// assertTriesEqual compares the fields that must be bit-identical between the
// full path and the IP-only / delegated path.
func assertTriesEqual(t *testing.T, label string, want, got []output.TrieResult) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("%s: trie count mismatch: want %d got %d", label, len(want), len(got))
	}
	// Both pipelines sort tries by name, so index alignment is valid.
	for i := range want {
		w, g := want[i], got[i]
		if w.Name != g.Name {
			t.Fatalf("%s: trie[%d] name mismatch: want %q got %q", label, i, w.Name, g.Name)
		}
		if w.Stats.TotalRequestsAfterFiltering != g.Stats.TotalRequestsAfterFiltering {
			t.Errorf("%s: trie %q TotalRequestsAfterFiltering: want %d got %d",
				label, w.Name, w.Stats.TotalRequestsAfterFiltering, g.Stats.TotalRequestsAfterFiltering)
		}
		if w.Stats.UniqueIPs != g.Stats.UniqueIPs {
			t.Errorf("%s: trie %q UniqueIPs: want %d got %d",
				label, w.Name, w.Stats.UniqueIPs, g.Stats.UniqueIPs)
		}
		if w.Stats.SkippedInvalidIPs != g.Stats.SkippedInvalidIPs {
			t.Errorf("%s: trie %q SkippedInvalidIPs: want %d got %d",
				label, w.Name, w.Stats.SkippedInvalidIPs, g.Stats.SkippedInvalidIPs)
		}
		if !reflect.DeepEqual(normalizeRanges(w.Stats.CIDRAnalysis), normalizeRanges(g.Stats.CIDRAnalysis)) {
			t.Errorf("%s: trie %q CIDRAnalysis mismatch:\n want %+v\n got  %+v",
				label, w.Name, normalizeRanges(w.Stats.CIDRAnalysis), normalizeRanges(g.Stats.CIDRAnalysis))
		}
		if len(w.Data) != len(g.Data) {
			t.Errorf("%s: trie %q cluster-set count: want %d got %d", label, w.Name, len(w.Data), len(g.Data))
			continue
		}
		for j := range w.Data {
			wc, gc := w.Data[j], g.Data[j]
			if wc.Parameters != gc.Parameters {
				t.Errorf("%s: trie %q cluster[%d] params mismatch: want %+v got %+v",
					label, w.Name, j, wc.Parameters, gc.Parameters)
			}
			if !reflect.DeepEqual(normalizeRanges(wc.DetectedRanges), normalizeRanges(gc.DetectedRanges)) {
				t.Errorf("%s: trie %q cluster[%d] DetectedRanges mismatch:\n want %+v\n got  %+v",
					label, w.Name, j, normalizeRanges(wc.DetectedRanges), normalizeRanges(gc.DetectedRanges))
			}
			if !reflect.DeepEqual(normalizeRanges(wc.MergedRanges), normalizeRanges(gc.MergedRanges)) {
				t.Errorf("%s: trie %q cluster[%d] MergedRanges mismatch:\n want %+v\n got  %+v",
					label, w.Name, j, normalizeRanges(wc.MergedRanges), normalizeRanges(gc.MergedRanges))
			}
		}
	}
}

// TestNoRequestsMatchesFullPath_Unfiltered verifies that the IP-only fast path
// (Static with no filters) produces a JSONOutput
// identical, in every field that matters, to StaticWithRequests.
func TestNoRequestsMatchesFullPath_Unfiltered(t *testing.T) {
	logFile, cleanup := testutil.GenerateTestLogFile(t, 50000)
	defer cleanup()

	logFormat := `%h %^ %^ [%t] "%r" %s %b "%^" "%u"`

	cfg := &config.Config{
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: logFormat,
		},
		StaticTries: map[string]*config.TrieConfig{
			"trie_a": {
				CIDRRanges: []string{"192.168.0.0/16", "10.0.0.0/8"},
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 100, MinDepth: 8, MaxDepth: 24, MeanSubnetDifference: 0.1},
					{MinClusterSize: 500, MinDepth: 12, MaxDepth: 32, MeanSubnetDifference: 0.2},
				},
			},
			"trie_b": {
				CIDRRanges: []string{"172.16.0.0/12"},
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 50, MinDepth: 8, MaxDepth: 16, MeanSubnetDifference: 0.15},
				},
			},
		},
	}

	full, _, err := StaticWithRequests(cfg)
	if err != nil {
		t.Fatalf("full path error: %v", err)
	}
	noReq, err := Static(cfg)
	if err != nil {
		t.Fatalf("no-requests path error: %v", err)
	}

	if full.General.TotalRequests != noReq.General.TotalRequests {
		t.Errorf("TotalRequests: full=%d noReq=%d", full.General.TotalRequests, noReq.General.TotalRequests)
	}
	if full.General.UniqueIPs != noReq.General.UniqueIPs {
		t.Errorf("General.UniqueIPs: full=%d noReq=%d", full.General.UniqueIPs, noReq.General.UniqueIPs)
	}
	assertTriesEqual(t, "unfiltered", full.Tries, noReq.Tries)
}

// TestNoRequestsMatchesFullPath_Filtered verifies that with a FILTERED config the
// NoRequests path delegates to the full path and produces the same output.
func TestNoRequestsMatchesFullPath_Filtered(t *testing.T) {
	logFile, cleanup := testutil.GenerateTestLogFile(t, 50000)
	defer cleanup()

	logFormat := `%h %^ %^ [%t] "%r" %s %b "%^" "%u"`

	cfg := &config.Config{
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: logFormat,
		},
		StaticTries: map[string]*config.TrieConfig{
			"filtered": {
				EndpointRegex: "api",
				CIDRRanges:    []string{"192.168.0.0/16"},
				ClusterArgSets: []config.ClusterArgSet{
					{MinClusterSize: 50, MinDepth: 8, MaxDepth: 24, MeanSubnetDifference: 0.1},
				},
			},
		},
	}

	full, _, err := StaticWithRequests(cfg)
	if err != nil {
		t.Fatalf("full path error: %v", err)
	}
	noReq, err := Static(cfg)
	if err != nil {
		t.Fatalf("no-requests path error: %v", err)
	}

	if full.General.TotalRequests != noReq.General.TotalRequests {
		t.Errorf("TotalRequests: full=%d noReq=%d", full.General.TotalRequests, noReq.General.TotalRequests)
	}
	if full.General.UniqueIPs != noReq.General.UniqueIPs {
		t.Errorf("General.UniqueIPs: full=%d noReq=%d", full.General.UniqueIPs, noReq.General.UniqueIPs)
	}
	assertTriesEqual(t, "filtered", full.Tries, noReq.Tries)
}
