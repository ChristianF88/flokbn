package config

import (
	"strings"
	"testing"
)

// A trie or window written as an array of tables (`[[static.name]]`) decodes
// to a list, not a table. It used to be reported as an unknown key of the
// parent section ("unknown key "name" in [static] section (want: logFile,
// ...)"), which names neither the mistake nor the fix. It is a wrong-typed
// section like `[[static]]` and gets the same hard error.
func TestLoadConfig_TrieSubTableMustBeTable(t *testing.T) {
	cases := []struct {
		name    string
		toml    string
		wantErr string
	}{
		{"static trie", "[[static.bots]]\nclusterArgSets = [[1000, 24, 32, 0.1]]\n",
			"section [static.bots] must be a table, got an array of tables (write it as a [static.bots] header followed by key = value lines)"},
		{"live window", "[live]\nport = \"9000\"\n[[live.window]]\nslidingWindowMaxSize = 10\n",
			"section [live.window] must be a table, got an array of tables (write it as a [live.window] header followed by key = value lines)"},
		// Several offenders: the first by name, whatever the map order.
		{"first by name", "[[static.b]]\n[[static.a]]\n[[static.c]]\n",
			"section [static.a] must be a table, got an array of tables (write it as a [static.a] header followed by key = value lines)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 20; i++ { // map order must not matter
				_, err := loadConfigString(t, tc.toml)
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("error differs\n got: %v\nwant: %s", err, tc.wantErr)
				}
			}
		})
	}
}

// Only an array of tables is a mis-written sub-table. Any other non-table
// value under [static] / [live] is still an unknown key of that section, and
// a recognized scalar key keeps its own type error.
func TestLoadConfig_NonTableValuesStayKeyErrors(t *testing.T) {
	report := loadAndReport(t, "[static]\nbots = \"x\"\nranges = [1, 2]\n", StaticMode)
	for _, want := range []string{
		`unknown key "bots" in [static] section (want: logFile, logFormat, plotPath)`,
		`unknown key "ranges" in [static] section (want: logFile, logFormat, plotPath)`,
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}

	_, err := loadConfigString(t, "[[static.logFile]]\nx = 1\n")
	if err == nil || !strings.Contains(err.Error(), "logFile must be a string") {
		t.Errorf("a scalar key written as an array of tables keeps its type error, got: %v", err)
	}
}

// AddCIDRRange is the --rangesCidr path: same rules and messages as a TOML
// cidrRanges entry, under the flag's own name.
func TestTrieConfig_AddCIDRRange(t *testing.T) {
	tc := &TrieConfig{}
	diags := &ConfigDiagnostics{}
	for i, value := range []string{"10.0.0.0/8", "192.168.1.7", "2001:db8::/32", "::1", "::ffff:192.168.1.0/120", "192.168.1.0/33"} {
		tc.AddCIDRRange("rangesCidr", "static.cli_trie", i, value, diags)
	}
	if want := []string{"10.0.0.0/8", "192.168.1.7/32"}; strings.Join(tc.CIDRRanges, ",") != strings.Join(want, ",") {
		t.Errorf("CIDRRanges = %v, want %v", tc.CIDRRanges, want)
	}
	want := []string{
		`[static.cli_trie] IPv6 not supported (IPv4-only tool) in rangesCidr[2]: "2001:db8::/32"`,
		`[static.cli_trie] IPv6 not supported (IPv4-only tool) in rangesCidr[3]: "::1"`,
		`[static.cli_trie] IPv6 not supported (IPv4-only tool) in rangesCidr[4]: "::ffff:192.168.1.0/120"`,
		`[static.cli_trie] invalid rangesCidr[5] "192.168.1.0/33": invalid CIDR address: 192.168.1.0/33`,
	}
	if strings.Join(diags.msgs, "\n") != strings.Join(want, "\n") {
		t.Errorf("diagnostics differ\n got: %s\nwant: %s", strings.Join(diags.msgs, "\n      "), strings.Join(want, "\n      "))
	}
}
