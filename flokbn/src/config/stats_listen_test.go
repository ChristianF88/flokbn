package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadConfig_StatsListenAndTopTalkers(t *testing.T) {
	configPath := writeTestConfig(t, `
[live]
port = "8080"
statsListen = "127.0.0.1:9090"
topTalkers = 15

[live.window_1]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 100
sleepBetweenIterations = 1
clusterArgSets = [[100, 24, 32, 0.5]]
useForJail = [true]
`)

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if cfg.Live.StatsListen != "127.0.0.1:9090" {
		t.Errorf("Expected StatsListen 127.0.0.1:9090, got %q", cfg.Live.StatsListen)
	}
	if cfg.Live.TopTalkers != 15 {
		t.Errorf("Expected TopTalkers 15, got %d", cfg.Live.TopTalkers)
	}
	// statsListen/topTalkers must be treated as live config keys, not trie sections.
	if len(cfg.LiveTries) != 1 {
		t.Errorf("Expected 1 live trie, got %d", len(cfg.LiveTries))
	}
}

func TestLoadConfig_StatsListenDefaultsOff(t *testing.T) {
	configPath := writeTestConfig(t, `
[live]
port = "8080"
`)

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if cfg.Live.StatsListen != "" {
		t.Errorf("Expected empty StatsListen, got %q", cfg.Live.StatsListen)
	}
	if cfg.Live.TopTalkers != 0 {
		t.Errorf("Expected TopTalkers 0, got %d", cfg.Live.TopTalkers)
	}
}

func TestValidateLive_StatsListen(t *testing.T) {
	base := func() *Config {
		return &Config{
			Global: &GlobalConfig{JailFile: "jail.json", BanFile: "ban.txt"},
			Live:   &LiveConfig{Port: "8080"},
			LiveTries: map[string]*SlidingTrieConfig{
				// Per-window required fields (slidingWindowMaxSize/MaxTime/
				// clusterArgSets) so ValidateLive's window checks pass and this
				// test stays focused on statsListen/topTalkers.
				"w": {
					SlidingWindowMaxSize: 100,
					SlidingWindowMaxTime: time.Hour,
					ClusterArgSets:       []ClusterArgSet{{MinClusterSize: 100, MinDepth: 24, MaxDepth: 32, MeanSubnetDifference: 0.5}},
				},
			},
		}
	}

	cases := []struct {
		name    string
		mutate  func(c *Config)
		wantSub string // empty = expect valid
	}{
		{"StatsListenUnset", func(c *Config) {}, ""},
		{"StatsListenHostPort", func(c *Config) { c.Live.StatsListen = "127.0.0.1:9090" }, ""},
		{"StatsListenPortOnly", func(c *Config) { c.Live.StatsListen = ":9090" }, ""},
		{"StatsListenNoPort", func(c *Config) { c.Live.StatsListen = "127.0.0.1" }, "statsListen"},
		{"TopTalkersNegative", func(c *Config) { c.Live.TopTalkers = -1 }, "topTalkers"},
		{"TopTalkersWithoutStatsListenIsInert", func(c *Config) { c.Live.TopTalkers = 5 }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(cfg)
			err := cfg.ValidateLive()
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("ValidateLive() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("ValidateLive() = %v, want error mentioning %q", err, tc.wantSub)
			}
		})
	}
}
