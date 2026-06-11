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
	configPath := writeTestConfig(t, `
[log]
level = "info"
verbosity = "high"
`)

	_, err := LoadConfig(configPath)
	if err == nil || !strings.Contains(err.Error(), "verbosity") {
		t.Fatalf("LoadConfig err = %v, want unknown-key error mentioning %q", err, "verbosity")
	}
}

func TestLoadConfig_LogSectionRejectsBadEnums(t *testing.T) {
	cases := []struct {
		name    string
		toml    string
		wantSub string
	}{
		{"BadLevel", "[log]\nlevel = \"verbose\"\n", "level"},
		{"BadFormat", "[log]\nformat = \"xml\"\n", "format"},
		{"NonStringLevel", "[log]\nlevel = 3\n", "level"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := writeTestConfig(t, tc.toml)
			_, err := LoadConfig(configPath)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("LoadConfig err = %v, want error mentioning %q", err, tc.wantSub)
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
