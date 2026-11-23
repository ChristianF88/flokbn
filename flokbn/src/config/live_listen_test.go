package config

import (
	"strings"
	"testing"
)

const liveListenBase = `
[global]
jailFile = "/tmp/flokbn-test-jail.json"
banFile = "/tmp/flokbn-test-ban.txt"

[live.win]
slidingWindowMaxTime = "1m"
slidingWindowMaxSize = 1000
clusterArgSets = [[100, 24, 32, 0.5]]
useForJail = [true]
`

// The Lumberjack port is unauthenticated, so without an explicit listen
// address it binds loopback - never every interface.
func TestLiveListen_DefaultsToLoopback(t *testing.T) {
	cfg, err := loadConfigString(t, liveListenBase+`
[live]
port = "9000"
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.GetListenAddr(); got != "127.0.0.1:9000" {
		t.Errorf("GetListenAddr() = %q, want 127.0.0.1:9000", got)
	}
	if DefaultLiveListen != "127.0.0.1" {
		t.Errorf("DefaultLiveListen = %q, want 127.0.0.1", DefaultLiveListen)
	}
}

func TestLiveListen_ExplicitAddresses(t *testing.T) {
	for listen, want := range map[string]string{
		"0.0.0.0":   "0.0.0.0:9000",
		"10.1.2.3":  "10.1.2.3:9000",
		"::1":       "[::1]:9000",
		"::":        "[::]:9000",
		"localhost": "localhost:9000",
	} {
		t.Run(listen, func(t *testing.T) {
			cfg, err := loadConfigString(t, liveListenBase+`
[live]
port = "9000"
listen = "`+listen+`"
`)
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if report := cfg.Validate(LiveMode).Report(); strings.Contains(report, "listen") {
				t.Fatalf("listen = %q rejected:\n%s", listen, report)
			}
			if got := cfg.GetListenAddr(); got != want {
				t.Errorf("GetListenAddr() = %q, want %q", got, want)
			}
		})
	}
}

// listen is an address only: a value carrying a port (or anything else that
// is not a plain address) is reported instead of producing a confusing bind
// error later.
func TestLiveListen_RejectsNonAddresses(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:9000", "localhost:9000", "[::1]", "10.0.0.0/8", "not an address"} {
		t.Run(listen, func(t *testing.T) {
			report := loadAndReport(t, liveListenBase+`
[live]
port = "9000"
listen = "`+listen+`"
`, LiveMode)
			if !strings.Contains(report, "invalid listen") {
				t.Errorf("listen = %q: report lacks \"invalid listen\":\n%s", listen, report)
			}
		})
	}
}

func TestLiveListen_WrongTypeIsHardError(t *testing.T) {
	_, err := loadConfigString(t, liveListenBase+`
[live]
port = "9000"
listen = 127
`)
	if err == nil || !strings.Contains(err.Error(), "listen must be a string") {
		t.Errorf("LoadConfig error = %v, want \"listen must be a string\"", err)
	}
}

// The unknown-key hint for [live] names listen among the valid keys.
func TestLiveListen_ListedAsValidKey(t *testing.T) {
	report := loadAndReport(t, `
[live]
port = "9000"
lisen = "0.0.0.0"
`, LiveMode)
	if !strings.Contains(report, "listen") {
		t.Errorf("unknown-key hint does not list listen:\n%s", report)
	}
}

func TestGetListenAddr_NilLive(t *testing.T) {
	if got := (&Config{}).GetListenAddr(); got != "127.0.0.1:" {
		t.Errorf("GetListenAddr() with no [live] = %q, want \"127.0.0.1:\"", got)
	}
}
