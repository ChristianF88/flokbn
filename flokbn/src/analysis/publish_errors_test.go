package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/output"
)

// publishErrorLog holds one /24 with enough requests to be detected by
// publishErrorCfg's cluster set, so the jail has something to save.
func publishErrorLog() string {
	var sb strings.Builder
	for i := 0; i < 300; i++ {
		sb.WriteString(logLine(fmt.Sprintf("10.9.8.%d", i%250), "/", "a"))
	}
	return sb.String()
}

func publishErrorCfg(t *testing.T, dir string, filtered bool) *config.Config {
	t.Helper()
	cfg := publishCfg(t, dir, publishErrorLog())
	if filtered {
		// A per-trie filter takes Static off the IP-only path.
		cfg.StaticTries["t"].EndpointRegex = "^/"
		compileTries(t, cfg.StaticTries)
	}
	return cfg
}

// TestStaticPublishFailures pins how each failure of the jail/ban publish step
// surfaces: the run fails, the JSON output names the failing stage followed by
// the generic jail_processing entry, and the analysis results are still there.
// Identical for both entrypoints, on the IP-only and on the filtered path.
func TestStaticPublishFailures(t *testing.T) {
	cases := []struct {
		name       string
		breakIt    func(t *testing.T, dir string, cfg *config.Config)
		errorTypes []string
		// errContains must appear in the returned error and in both messages.
		errContains string
	}{
		{
			name: "missing_whitelist",
			breakIt: func(t *testing.T, dir string, cfg *config.Config) {
				cfg.Global.Whitelist = filepath.Join(dir, "no-such-whitelist.txt")
			},
			errorTypes:  []string{"whitelist_load", "jail_processing"},
			errContains: "no-such-whitelist.txt",
		},
		{
			name: "missing_blacklist",
			breakIt: func(t *testing.T, dir string, cfg *config.Config) {
				cfg.Global.Blacklist = filepath.Join(dir, "no-such-blacklist.txt")
			},
			errorTypes:  []string{"blacklist_load", "jail_processing"},
			errContains: "no-such-blacklist.txt",
		},
		{
			name: "corrupt_jail",
			breakIt: func(t *testing.T, dir string, cfg *config.Config) {
				writeTestFile(t, dir, "jail.json", "{ this is not json")
			},
			errorTypes:  []string{"jail_load", "jail_processing"},
			errContains: "",
		},
		{
			name: "jail_not_writable",
			breakIt: func(t *testing.T, dir string, cfg *config.Config) {
				cfg.Global.JailFile = filepath.Join(dir, "missing-dir", "jail.json")
			},
			errorTypes:  []string{"jail_save", "jail_processing"},
			errContains: "missing-dir",
		},
		{
			name: "ban_file_not_writable",
			breakIt: func(t *testing.T, dir string, cfg *config.Config) {
				cfg.Global.BanFile = filepath.Join(dir, "missing-dir", "ban.txt")
			},
			errorTypes:  []string{"banfile_write", "jail_processing"},
			errContains: "missing-dir",
		},
	}

	entrypoints := map[string]func(*config.Config) (*output.JSONOutput, error){
		"Static": Static,
		"StaticWithRequests": func(cfg *config.Config) (*output.JSONOutput, error) {
			out, _, err := StaticWithRequests(cfg)
			return out, err
		},
	}

	for _, tc := range cases {
		for epName, run := range entrypoints {
			for _, filtered := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/filtered=%v", tc.name, epName, filtered), func(t *testing.T) {
					dir := t.TempDir()
					cfg := publishErrorCfg(t, dir, filtered)
					tc.breakIt(t, dir, cfg)

					out, err := run(cfg)
					if err == nil {
						t.Fatalf("expected an error, got none; errors: %+v", out.Errors)
					}
					if out == nil {
						t.Fatal("expected the partial output next to the error")
					}
					var types []string
					for _, e := range out.Errors {
						types = append(types, e.Type)
						if !strings.Contains(e.Message, tc.errContains) {
							t.Errorf("error %q message %q does not mention %q", e.Type, e.Message, tc.errContains)
						}
						if e.Count != 1 {
							t.Errorf("error %q count = %d, want 1", e.Type, e.Count)
						}
					}
					if !reflect.DeepEqual(types, tc.errorTypes) {
						t.Errorf("error types = %v, want %v", types, tc.errorTypes)
					}
					if !strings.Contains(err.Error(), tc.errContains) {
						t.Errorf("returned error %q does not mention %q", err, tc.errContains)
					}
					// The generic entry wraps the returned error text.
					last := out.Errors[len(out.Errors)-1]
					if want := "Failed to process jail with whitelist/blacklist: " + err.Error(); last.Message != want {
						t.Errorf("jail_processing message = %q, want %q", last.Message, want)
					}
					// The analysis itself completed and is reported.
					if len(out.Tries) != 1 || len(out.Tries[0].Data) != 1 || len(out.Tries[0].Data[0].MergedRanges) != 1 {
						t.Errorf("analysis results missing from the failed run: %+v", out.Tries)
					}
				})
			}
		}
	}
}

// TestStaticPublishMessages pins the two informational entries of a successful
// publish and the files it leaves behind.
func TestStaticPublishMessages(t *testing.T) {
	for _, filtered := range []bool{false, true} {
		t.Run(fmt.Sprintf("filtered=%v", filtered), func(t *testing.T) {
			dir := t.TempDir()
			cfg := publishErrorCfg(t, dir, filtered)
			cfg.Global.Whitelist = writeTestFile(t, dir, "whitelist.txt", "10.9.0.0/16\n")
			cfg.Global.Blacklist = writeTestFile(t, dir, "blacklist.txt", "198.51.100.0/24\n203.0.113.9\n")

			out, err := Static(cfg)
			if err != nil {
				t.Fatalf("Static: %v", err)
			}
			if len(out.Errors) != 0 {
				t.Errorf("unexpected errors: %+v", out.Errors)
			}
			want := map[string]output.Warning{
				"whitelist_applied": {Type: "whitelist_applied", Message: "Whitelist filtering prevented 1 CIDRs from being added to jail", Count: 0},
				"blacklist_applied": {Type: "blacklist_applied", Message: "Added 2 manual blacklist entries to ban file", Count: 0},
			}
			seen := 0
			for _, w := range out.Warnings {
				if exp, ok := want[w.Type]; ok {
					seen++
					if w != exp {
						t.Errorf("warning = %+v, want %+v", w, exp)
					}
				}
			}
			if seen != len(want) {
				t.Errorf("warnings = %+v, want both whitelist_applied and blacklist_applied", out.Warnings)
			}

			bans := banFileCIDRs(t, cfg.GetBanFile())
			if !reflect.DeepEqual(bans, map[string]bool{"198.51.100.0/24": true, "203.0.113.9/32": true}) {
				t.Errorf("ban file CIDRs = %v, want only the two blacklist entries", bans)
			}
			// Nothing reached the jail (the only detection is whitelisted) and no
			// ban expired, so the jail file is not created.
			if _, err := os.Stat(cfg.GetJailFile()); !os.IsNotExist(err) {
				t.Errorf("jail file should not exist after a run that changed nothing, stat err = %v", err)
			}
		})
	}
}

// TestStaticUnreadableIPWhitelistWithoutJail: without jail/ban files the IP
// whitelist is only counted for the output, and an unreadable one counts as
// zero instead of failing the run (the config barrier reports it earlier for
// CLI runs).
func TestStaticUnreadableIPWhitelistWithoutJail(t *testing.T) {
	for _, filtered := range []bool{false, true} {
		t.Run(fmt.Sprintf("filtered=%v", filtered), func(t *testing.T) {
			dir := t.TempDir()
			cfg := publishErrorCfg(t, dir, filtered)
			cfg.Global = &config.GlobalConfig{Whitelist: filepath.Join(dir, "no-such-whitelist.txt")}

			out, err := Static(cfg)
			if err != nil {
				t.Fatalf("Static: %v", err)
			}
			if len(out.Errors) != 0 {
				t.Errorf("unexpected errors: %+v", out.Errors)
			}
			if out.GlobalFilters.IPWhitelistCIDRs != 0 {
				t.Errorf("IPWhitelistCIDRs = %d, want 0", out.GlobalFilters.IPWhitelistCIDRs)
			}
		})
	}
}
