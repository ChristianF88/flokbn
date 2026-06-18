package config

import (
	"strings"
	"testing"
)

func TestLoadConfig_LogSection(t *testing.T) {
	configPath := writeTestConfig(t, `
[log]
level = "debug"
format = "json"

[live]
port = "8080"
`)

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want debug", cfg.Log.Level)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Log.Format = %q, want json", cfg.Log.Format)
	}
}

func TestLoadConfig_LogSectionDefaultsWhenAbsent(t *testing.T) {
	configPath := writeTestConfig(t, `
[live]
port = "8080"
`)

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if cfg.Log == nil {
		t.Fatal("Log = nil, want non-nil default")
	}
	if cfg.Log.Level != "" || cfg.Log.Format != "" {
		t.Errorf("Log = %+v, want empty defaults", cfg.Log)
	}
}

func TestLoadConfig_LogSectionRejectsUnknownKey(t *testing.T) {
	// CFG-02: a [log] unknown key is now a collect-all diagnostic (LoadConfig
	// succeeds; it surfaces via Validate). MSG text preserved.
	configPath := writeTestConfig(t, `
[log]
level = "info"
verbosity = "high"
`)
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig should succeed (unknown key surfaces via Validate): %v", err)
	}
	report := cfg.Validate(StaticMode).Report()
	if !strings.Contains(report, "verbosity") {
		t.Fatalf("Validate report = %q, want unknown-key diagnostic mentioning %q", report, "verbosity")
	}
}

func TestLoadConfig_LogSectionRejectsBadEnums(t *testing.T) {
	// BadLevel/BadFormat are value-enum failures: collect-all via Validate.
	// NonStringLevel is a wrong-TYPE failure: it STAYS a HARD LoadConfig error.
	cases := []struct {
		name    string
		toml    string
		wantSub string
		hard    bool
	}{
		{"BadLevel", "[log]\nlevel = \"verbose\"\n", "level", false},
		{"BadFormat", "[log]\nformat = \"xml\"\n", "format", false},
		{"NonStringLevel", "[log]\nlevel = 3\n", "level", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := writeTestConfig(t, tc.toml)
			cfg, err := LoadConfig(configPath)
			if tc.hard {
				if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
					t.Fatalf("LoadConfig err = %v, want hard error mentioning %q", err, tc.wantSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadConfig should succeed (enum surfaces via Validate): %v", err)
			}
			report := cfg.Validate(StaticMode).Report()
			if !strings.Contains(report, tc.wantSub) {
				t.Fatalf("Validate report = %q, want diagnostic mentioning %q", report, tc.wantSub)
			}
		})
	}
}

func TestLoadConfig_LogSectionCaseInsensitiveEnums(t *testing.T) {
	configPath := writeTestConfig(t, `
[log]
level = "WARN"
format = "TEXT"
`)

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if cfg.Log.Level != "WARN" || cfg.Log.Format != "TEXT" {
		t.Errorf("Log = %+v, want raw values preserved", cfg.Log)
	}
}
