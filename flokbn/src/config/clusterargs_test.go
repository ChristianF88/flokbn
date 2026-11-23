package config

import (
	"fmt"
	"strings"
	"testing"
)

// clusterArgCase is one cluster-arg set written both as a TOML row and as the
// flat string form the CLI flags produce. The TOML and flag parsers must agree
// on every case (C1): they share validateClusterArgValues.
type clusterArgCase struct {
	name string
	toml string   // row literal, e.g. "[100, 24, 32, 0.1]"
	args []string // the same four values as flag strings
	want string   // substring the rejection must contain ("" = must be accepted)
}

var clusterArgCases = []clusterArgCase{
	{"valid", "[100, 24, 32, 0.1]", []string{"100", "24", "32", "0.1"}, ""},
	{"valid lower bounds", "[1, 0, 0, 0]", []string{"1", "0", "0", "0"}, ""},
	{"valid upper bounds", "[4294967295, 32, 32, 2.0]", []string{"4294967295", "32", "32", "2"}, ""},
	{"valid integral float", "[100.0, 24.0, 32.0, 0.1]", []string{"100.0", "24.0", "32.0", "0.1"}, ""},

	{"minClusterSize zero", "[0, 24, 32, 0.1]", []string{"0", "24", "32", "0.1"}, "minClusterSize"},
	{"minClusterSize negative", "[-1, 24, 32, 0.1]", []string{"-1", "24", "32", "0.1"}, "minClusterSize"},
	{"minClusterSize fractional", "[1.5, 24, 32, 0.1]", []string{"1.5", "24", "32", "0.1"}, "minClusterSize"},
	{"minClusterSize over uint32", "[4294967296, 24, 32, 0.1]", []string{"4294967296", "24", "32", "0.1"}, "minClusterSize"},
	{"minClusterSize NaN", "[nan, 24, 32, 0.1]", []string{"NaN", "24", "32", "0.1"}, "minClusterSize"},
	{"minClusterSize Inf", "[inf, 24, 32, 0.1]", []string{"Inf", "24", "32", "0.1"}, "minClusterSize"},

	{"minDepth negative", "[100, -1, 32, 0.1]", []string{"100", "-1", "32", "0.1"}, "minDepth"},
	{"minDepth fractional", "[100, 24.5, 32, 0.1]", []string{"100", "24.5", "32", "0.1"}, "minDepth"},
	{"minDepth NaN", "[100, nan, 32, 0.1]", []string{"100", "NaN", "32", "0.1"}, "minDepth"},
	{"minDepth over 32", "[100, 33, 33, 0.1]", []string{"100", "33", "33", "0.1"}, "minDepth"},
	{"minDepth over maxDepth", "[100, 32, 24, 0.1]", []string{"100", "32", "24", "0.1"}, "minDepth (32) must be <= maxDepth (24)"},

	{"maxDepth over 32", "[100, 24, 33, 0.1]", []string{"100", "24", "33", "0.1"}, "maxDepth"},
	{"maxDepth fractional", "[100, 24, 31.5, 0.1]", []string{"100", "24", "31.5", "0.1"}, "maxDepth"},
	{"maxDepth huge", "[100, 24, 4294967328, 0.1]", []string{"100", "24", "4294967328", "0.1"}, "maxDepth"},
	{"maxDepth negative", "[100, 0, -3, 0.1]", []string{"100", "0", "-3", "0.1"}, "maxDepth"},
	{"maxDepth Inf", "[100, 24, inf, 0.1]", []string{"100", "24", "+Inf", "0.1"}, "maxDepth"},

	{"threshold negative", "[100, 24, 32, -0.1]", []string{"100", "24", "32", "-0.1"}, "meanSubnetDifference"},
	{"threshold over 2", "[100, 24, 32, 2.5]", []string{"100", "24", "32", "2.5"}, "meanSubnetDifference"},
	{"threshold NaN", "[100, 24, 32, nan]", []string{"100", "24", "32", "NaN"}, "meanSubnetDifference"},
	{"threshold Inf", "[100, 24, 32, inf]", []string{"100", "24", "32", "Inf"}, "meanSubnetDifference"},
}

// TestClusterArgs_TOMLAndFlagsAgree: every out-of-range cluster-arg value is
// rejected by BOTH the TOML path (static and live tables) and the flag path,
// and every valid one is accepted by both with identical typed results.
func TestClusterArgs_TOMLAndFlagsAgree(t *testing.T) {
	for _, tc := range clusterArgCases {
		t.Run(tc.name, func(t *testing.T) {
			flagSets, flagErr := ParseClusterArgSetsFromStrings(tc.args)

			staticCfg, err := loadConfigString(t, fmt.Sprintf("[static.t]\nclusterArgSets = [%s]\n", tc.toml))
			if err != nil {
				t.Fatalf("LoadConfig(static): %v", err)
			}
			staticReport := staticCfg.Validate(StaticMode)

			liveCfg, err := loadConfigString(t, fmt.Sprintf(`
[global]
jailFile = %q
banFile = %q
[live]
port = "9000"
[live.w]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 10
clusterArgSets = [%s]
`, t.TempDir()+"/jail.json", t.TempDir()+"/ban.txt", tc.toml))
			if err != nil {
				t.Fatalf("LoadConfig(live): %v", err)
			}
			liveReport := liveCfg.Validate(LiveMode)

			if tc.want == "" {
				if flagErr != nil {
					t.Errorf("flags rejected a valid set: %v", flagErr)
				}
				if staticReport.HasErrors() {
					t.Errorf("static TOML rejected a valid set:\n%s", staticReport.Report())
				}
				if liveReport.HasErrors() {
					t.Errorf("live TOML rejected a valid set:\n%s", liveReport.Report())
				}
				tomlSets := staticCfg.StaticTries["t"].ClusterArgSets
				if len(flagSets) != 1 || len(tomlSets) != 1 || flagSets[0] != tomlSets[0] {
					t.Errorf("flag and TOML results differ: flags=%+v toml=%+v", flagSets, tomlSets)
				}
				if liveSets := liveCfg.LiveTries["w"].ClusterArgSets; len(liveSets) != 1 || len(tomlSets) != 1 || liveSets[0] != tomlSets[0] {
					t.Errorf("live and static TOML results differ: live=%+v static=%+v", liveSets, tomlSets)
				}
				return
			}

			if flagErr == nil {
				t.Errorf("flags accepted %v, want rejection naming %q (got %+v)", tc.args, tc.want, flagSets)
			} else if !strings.Contains(flagErr.Error(), tc.want) {
				t.Errorf("flag error %q does not contain %q", flagErr, tc.want)
			}
			for mode, d := range map[string]*ConfigDiagnostics{"static": staticReport, "live": liveReport} {
				if !strings.Contains(d.Report(), tc.want) || !strings.Contains(d.Report(), "clusterArgSets row 0") {
					t.Errorf("%s TOML report should reject row 0 naming %q, got:\n%s", mode, tc.want, d.Report())
				}
			}
			if sets := staticCfg.StaticTries["t"].ClusterArgSets; len(sets) != 0 {
				t.Errorf("a rejected row must not survive on the trie, got %+v", sets)
			}
		})
	}
}

// TestClusterArgs_OneDiagnosticPerRow: a row with several bad values yields one
// diagnostic line (naming each problem), so the per-row count stays stable for
// the useForJail alignment guard.
func TestClusterArgs_OneDiagnosticPerRow(t *testing.T) {
	cfg, err := loadConfigString(t, "[static.t]\nclusterArgSets = [[0, 40, 50, 9]]\n")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	d := cfg.Validate(StaticMode)
	if d.Len() != 1 {
		t.Fatalf("want exactly 1 diagnostic, got %d:\n%s", d.Len(), d.Report())
	}
	for _, want := range []string{"minClusterSize", "minDepth", "maxDepth", "meanSubnetDifference"} {
		if !strings.Contains(d.Report(), want) {
			t.Errorf("report should name %s, got:\n%s", want, d.Report())
		}
	}
}
