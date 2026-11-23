package analysis

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
)

// alignmentLog is 256 requests, one per address of 10.1.1.0/24: the valid
// cluster set below ([100,24,24,0.5]) detects exactly 10.1.1.0/24.
func alignmentLog() string {
	var sb strings.Builder
	for i := 0; i < 256; i++ {
		fmt.Fprintf(&sb, "10.1.1.%d - - [01/Jan/2023:12:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"a\"\n", i)
	}
	return sb.String()
}

// TestInvalidClusterSetKeepsUseForJailAligned: processClustering used to skip
// an invalid cluster arg set without appending anything to TrieResult.Data,
// while ProcessJailWithWhitelist pairs Data[i] with UseForJail[i] by position.
// Every set after an invalid one therefore took the useForJail flag of its
// left neighbour - a set marked "do not jail" could be banned, and a set
// marked for the jail could be ignored.
func TestInvalidClusterSetKeepsUseForJailAligned(t *testing.T) {
	invalid := config.ClusterArgSet{MinClusterSize: 100, MinDepth: 32, MaxDepth: 24, MeanSubnetDifference: 0.5}
	valid := config.ClusterArgSet{MinClusterSize: 100, MinDepth: 24, MaxDepth: 24, MeanSubnetDifference: 0.5}
	const detected = "10.1.1.0/24"

	runs := map[string]func(*config.Config) (*output.JSONOutput, error){
		"Static": Static,
		"StaticWithRequests": func(cfg *config.Config) (*output.JSONOutput, error) {
			out, _, err := StaticWithRequests(cfg)
			return out, err
		},
	}
	cases := []struct {
		name       string
		useForJail []bool
		wantBanned bool
	}{
		{"invalid set flagged, valid set not: nothing may be banned", []bool{true, false}, false},
		{"valid set flagged: its range must be banned", []bool{false, true}, true},
	}

	for runName, run := range runs {
		for _, tc := range cases {
			t.Run(runName+"/"+tc.name, func(t *testing.T) {
				cfg := publishCfg(t, t.TempDir(), alignmentLog())
				cfg.StaticTries["t"] = &config.TrieConfig{
					ClusterArgSets: []config.ClusterArgSet{invalid, valid},
					UseForJail:     tc.useForJail,
				}

				out, err := run(cfg)
				if err != nil {
					t.Fatalf("run failed: %v", err)
				}

				hasErr := false
				for _, e := range out.Errors {
					if e.Type == "invalid_depth_params" {
						hasErr = true
					}
				}
				if !hasErr {
					t.Error("missing invalid_depth_params error for the invalid set")
				}

				data := out.Tries[0].Data
				if len(data) != 2 {
					t.Fatalf("len(Data) = %d, want 2 (one entry per configured cluster set, in config order)", len(data))
				}
				if got := data[0].Parameters; got.MinDepth != invalid.MinDepth || got.MaxDepth != invalid.MaxDepth {
					t.Errorf("Data[0] parameters = %+v, want the invalid set's parameters", got)
				}
				if data[0].DetectedRanges == nil || data[0].MergedRanges == nil ||
					len(data[0].DetectedRanges) != 0 || len(data[0].MergedRanges) != 0 {
					t.Errorf("Data[0] must be an empty placeholder with non-nil range slices, got %+v", data[0])
				}
				if len(data[1].MergedRanges) != 1 || data[1].MergedRanges[0].CIDR != detected {
					t.Fatalf("Data[1] merged ranges = %+v, want [%s]", data[1].MergedRanges, detected)
				}

				if banned := banFileCIDRs(t, cfg.GetBanFile())[detected]; banned != tc.wantBanned {
					t.Errorf("%s banned = %v, want %v (useForJail = %v)", detected, banned, tc.wantBanned, tc.useForJail)
				}
			})
		}
	}
}
