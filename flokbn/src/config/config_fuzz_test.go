package config

import (
	"os"
	"testing"
)

func FuzzLoadConfig(f *testing.F) {
	// Seed with minimal valid config
	f.Add([]byte(`
[global]
[static]
logFormat = "%h %^ %^ [%t] \"%r\" %s %b"
[static.trie_1]
clusterArgSets = [[100, 24, 32, 0.1]]
`))

	// Seed with empty config
	f.Add([]byte(""))

	// Seed with just global section
	f.Add([]byte(`
[global]
jailFile = "/tmp/jail.json"
banFile = "/tmp/ban.txt"
whitelist = "/tmp/wl.txt"
blacklist = "/tmp/bl.txt"
`))

	// Seed with live config
	f.Add([]byte(`
[live]
port = "8080"
[live.sliding_trie_1]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 10000
sleepBetweenIterations = 30
clusterArgSets = [[200, 30, 32, 0.2]]
`))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()
		configPath := tmpDir + "/fuzz.toml"
		if err := os.WriteFile(configPath, data, 0644); err != nil {
			return
		}
		// Should not panic — invalid configs return errors
		LoadConfig(configPath)
	})
}

func FuzzParseClusterArgSetsFromStrings(f *testing.F) {
	// Seed with valid sets
	f.Add("1000,24,32,0.1")
	f.Add("500,16,24,0.2")
	// Edge cases
	f.Add("")
	f.Add("abc,def,ghi,jkl")
	f.Add("0,0,0,0")
	f.Add("999999999,32,32,1.0")
	f.Add("100,24,32")     // wrong field count
	f.Add("100,32,24,0.1") // minDepth > maxDepth

	f.Fuzz(func(t *testing.T, s string) {
		if s == "" {
			return
		}
		// Split by comma to create the args slice
		args := splitComma(s)
		// Should not panic
		ParseClusterArgSetsFromStrings(args)
	})
}

// splitComma splits a string by commas without importing strings
func splitComma(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}
