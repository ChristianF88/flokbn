package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// C4: README and --help describe the list files as "IP/CIDR" and
// config_examples/README.md shows a bare address, but loadCIDRFile rejected
// one. A bare IPv4 address is a single host: it loads as /32 so every
// downstream net.ParseCIDR consumer accepts it.
func TestLoadCIDRFile_BareIPv4BecomesSlash32(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	content := "# header\n192.168.1.0/24    # Internal network\n10.0.0.1          # Specific IP\n203.0.113.9\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := loadCIDRFile(path)
	if err != nil {
		t.Fatalf("loadCIDRFile: %v", err)
	}
	want := []string{"192.168.1.0/24", "10.0.0.1/32", "203.0.113.9/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loadCIDRFile = %v, want %v", got, want)
	}
}

// A bare IPv6 address stays rejected, and is named as an IPv6 problem rather
// than a generic format error.
func TestLoadCIDRFile_BareIPv6StillRejected(t *testing.T) {
	for _, addr := range []string{"2001:db8::1", "::1", "::ffff:192.168.1.1"} {
		path := filepath.Join(t.TempDir(), "list.txt")
		if err := os.WriteFile(path, []byte("10.0.0.0/8\n"+addr+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := loadCIDRFile(path)
		if err == nil {
			t.Fatalf("loadCIDRFile accepted bare IPv6 %q", addr)
		}
		if !strings.Contains(err.Error(), "IPv6 not supported") || !strings.Contains(err.Error(), path+":2:") {
			t.Errorf("error for %q should say IPv6 not supported with path:line, got: %v", addr, err)
		}
	}
}

// The TOML cidrRanges key follows the same rule as --rangesCidr and the list
// files: a bare IPv4 is stored as /32, IPv6 stays rejected.
func TestLoadConfig_CidrRangesBareIPv4BecomesSlash32(t *testing.T) {
	cfg, err := loadConfigString(t, `
[static.t]
cidrRanges = ["10.0.0.0/8", "1.2.3.4"]
`)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if d := cfg.Validate(StaticMode); d.HasErrors() {
		t.Fatalf("bare IPv4 in cidrRanges should validate, got:\n%s", d.Report())
	}
	want := []string{"10.0.0.0/8", "1.2.3.4/32"}
	if got := cfg.StaticTries["t"].CIDRRanges; !reflect.DeepEqual(got, want) {
		t.Fatalf("CIDRRanges = %v, want %v", got, want)
	}

	report := loadAndReport(t, `
[static.t]
cidrRanges = ["2001:db8::1"]
`, StaticMode)
	if !strings.Contains(report, "IPv6 not supported") {
		t.Fatalf("bare IPv6 in cidrRanges must stay rejected as IPv6, got:\n%s", report)
	}
}
