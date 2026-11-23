package config

import (
	"strings"
	"testing"
)

// C6: a regex diagnostic used to read "invalid useragentRegex pattern: ..."
// with no trie name, and a trie with two bad patterns reported only the first.
func TestRegexDiagnosticsNameTrieAndReportBothFields(t *testing.T) {
	cfg, err := loadConfigString(t, `
[static.alpha]
useragentRegex = "(unclosed"
endpointRegex = "[z-a]"

[static.beta]
endpointRegex = "*leading"
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	d := cfg.Validate(StaticMode)
	report := d.Report()
	if d.Len() != 3 {
		t.Fatalf("want 3 regex diagnostics, got %d:\n%s", d.Len(), report)
	}
	for _, want := range []string{
		"[static.alpha] invalid useragentRegex pattern",
		"[static.alpha] invalid endpointRegex pattern",
		"[static.beta] invalid endpointRegex pattern",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report should contain %q, got:\n%s", want, report)
		}
	}
}

func TestRegexDiagnosticsNameLiveWindow(t *testing.T) {
	cfg, err := loadConfigString(t, `
[live.win]
useragentRegex = "(unclosed"
endpointRegex = "[z-a]"
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	report := cfg.Validate(LiveMode).Report()
	for _, want := range []string{
		"[live.win] invalid useragentRegex pattern",
		"[live.win] invalid endpointRegex pattern",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report should contain %q, got:\n%s", want, report)
		}
	}
}

// CompileRegex (the error-returning wrapper) reports both failures too, and a
// bad pattern in one field does not stop the other field from compiling.
func TestCompileRegexFieldsAreIndependent(t *testing.T) {
	tc := &TrieConfig{UserAgentRegex: "(unclosed", EndpointRegex: "[z-a]"}
	err := tc.CompileRegex()
	if err == nil {
		t.Fatal("want an error for two bad patterns")
	}
	for _, want := range []string{"invalid useragentRegex pattern", "invalid endpointRegex pattern"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should contain %q, got: %v", want, err)
		}
	}

	stc := &SlidingTrieConfig{UserAgentRegex: "(unclosed", EndpointRegex: "^/api/"}
	if err := stc.CompileRegex(); err == nil || !strings.Contains(err.Error(), "invalid useragentRegex pattern") {
		t.Fatalf("want a useragentRegex error, got: %v", err)
	}
	if stc.endpointRegexCompiled == nil {
		t.Error("the valid endpointRegex must still be compiled")
	}
	if stc.userAgentRegexCompiled != nil || stc.userAgentPrefilter != nil {
		t.Error("the failed useragentRegex must leave both the regex and its prefilter nil")
	}
}
