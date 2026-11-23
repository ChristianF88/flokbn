package config

import (
	"strings"
	"testing"
)

// C3: a known top-level section written with the wrong TOML type (a scalar, an
// array, or an array of tables) used to be dropped silently, leaving the
// section empty - e.g. `[[global]]` nullified whitelist filtering while the run
// reported success. It must fail the load, naming the section.
func TestLoadConfig_TopLevelSectionMustBeTable(t *testing.T) {
	tests := []struct {
		name    string
		content string
		section string
		got     string
	}{
		{"global string", `global = "x"`, "[global]", "a string"},
		{"global array of tables", "[[global]]\nwhitelist = \"w.txt\"", "[global]", "an array of tables"},
		{"static integer", `static = 1`, "[static]", "an integer"},
		{"static array of tables", "[[static]]\nlogFile = \"a.log\"", "[static]", "an array of tables"},
		{"live array of tables", "[[live]]\nport = \"9000\"", "[live]", "an array of tables"},
		{"live boolean", `live = true`, "[live]", "a boolean"},
		{"log array", `log = ["debug"]`, "[log]", "an array"},
		{"log float", `log = 1.5`, "[log]", "a float"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadConfigString(t, tt.content)
			if err == nil {
				t.Fatalf("LoadConfig accepted a non-table %s section: %+v", tt.section, cfg)
			}
			msg := err.Error()
			if !strings.Contains(msg, "section "+tt.section+" must be a table") {
				t.Errorf("error should say the section must be a table, got: %v", err)
			}
			if !strings.Contains(msg, tt.got) {
				t.Errorf("error should name the actual type %q, got: %v", tt.got, err)
			}
		})
	}
}

// Proper tables (including empty ones and inline tables) keep loading.
func TestLoadConfig_TopLevelTablesStillLoad(t *testing.T) {
	for _, content := range []string{
		"[global]\n[static]\n[live]\n[log]\n",
		"global = {}\nstatic = { logFile = \"a.log\" }\n",
		"",
	} {
		if _, err := loadConfigString(t, content); err != nil {
			t.Errorf("LoadConfig(%q) should succeed: %v", content, err)
		}
	}
}
