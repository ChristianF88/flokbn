package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file locks in the IPv4-only boundary fix in loadCIDRFile. net.ParseCIDR
// accepts IPv6, which would otherwise reach the uint32 numeric hot path in the
// cidr package and corrupt IPv4 ban computation. loadCIDRFile now rejects any
// non-IPv4 CIDR with a clear "IPv6 CIDR not supported" error at the boundary.

// An IPv6 CIDR line must be rejected with a clear error.
func TestLoadCIDRFile_RejectsIPv6(t *testing.T) {
	cidrFile := filepath.Join(t.TempDir(), "ipv6.txt")
	if err := os.WriteFile(cidrFile, []byte("2001:db8::/32\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadCIDRFile(cidrFile)
	if err == nil {
		t.Fatal("expected error for IPv6 CIDR, got nil")
	}
	if !strings.Contains(err.Error(), "IPv6 CIDR not supported") {
		t.Fatalf("error does not mention IPv6/not supported: %v", err)
	}
}

// The IPv6 default route "::/0" is the most dangerous case (it used to wipe every
// IPv4 ban when placed in a whitelist). It must be rejected at load time.
func TestLoadCIDRFile_RejectsIPv6DefaultRoute(t *testing.T) {
	cidrFile := filepath.Join(t.TempDir(), "v6default.txt")
	if err := os.WriteFile(cidrFile, []byte("::/0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadCIDRFile(cidrFile)
	if err == nil {
		t.Fatal("expected error for ::/0, got nil")
	}
	if !strings.Contains(err.Error(), "IPv6 CIDR not supported") {
		t.Fatalf("error does not mention IPv6/not supported: %v", err)
	}
}

// IPv4-mapped IPv6 (::ffff:a.b.c.d/120) has a non-nil To4() but a 16-byte mask,
// so the old To4()==nil guard let it slip past the boundary into the numeric hot
// path. The mask-length check rejects it like any other IPv6 form.
func TestLoadCIDRFile_RejectsMappedIPv6(t *testing.T) {
	cidrFile := filepath.Join(t.TempDir(), "mapped.txt")
	if err := os.WriteFile(cidrFile, []byte("::ffff:1.2.3.0/120\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadCIDRFile(cidrFile)
	if err == nil {
		t.Fatal("expected error for IPv4-mapped IPv6 CIDR, got nil")
	}
	if !strings.Contains(err.Error(), "IPv6 CIDR not supported") {
		t.Fatalf("error does not mention IPv6/not supported: %v", err)
	}
}

// A valid IPv4-only file loads fine and preserves entries in order.
func TestLoadCIDRFile_ValidIPv4LoadsFine(t *testing.T) {
	cidrFile := filepath.Join(t.TempDir(), "ipv4.txt")
	content := "# comment\n192.168.1.0/24\n10.0.0.0/8\n\n172.16.0.0/12\n"
	if err := os.WriteFile(cidrFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cidrs, err := loadCIDRFile(cidrFile)
	if err != nil {
		t.Fatalf("valid IPv4 file errored: %v", err)
	}

	want := []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"}
	if len(cidrs) != len(want) {
		t.Fatalf("expected %d CIDRs, got %d: %v", len(want), len(cidrs), cidrs)
	}
	for i := range want {
		if cidrs[i] != want[i] {
			t.Errorf("CIDR[%d] = %q, want %q", i, cidrs[i], want[i])
		}
	}
}

// A file mixing valid IPv4 lines with one IPv6 line must error, and the error
// must point at the right line number (the IPv6 line, here line 3).
func TestLoadCIDRFile_MixedFileErrorsAtIPv6Line(t *testing.T) {
	cidrFile := filepath.Join(t.TempDir(), "mixed.txt")
	// line 1: 192.168.1.0/24 (ok)
	// line 2: 10.0.0.0/8     (ok)
	// line 3: 2001:db8::/32  (IPv6 -> reject here)
	// line 4: 172.16.0.0/12  (ok, but never reached)
	content := "192.168.1.0/24\n10.0.0.0/8\n2001:db8::/32\n172.16.0.0/12\n"
	if err := os.WriteFile(cidrFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadCIDRFile(cidrFile)
	if err == nil {
		t.Fatal("expected error for mixed IPv4/IPv6 file, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "IPv6 CIDR not supported") {
		t.Fatalf("error does not mention IPv6/not supported: %v", err)
	}
	if !strings.Contains(msg, "line 3") {
		t.Fatalf("error does not point at line 3 (the IPv6 line): %v", err)
	}
	// Sanity: the offending line text should be echoed for operator clarity.
	if !strings.Contains(msg, "2001:db8::/32") {
		t.Fatalf("error does not echo the offending IPv6 line: %v", err)
	}
}

// Comment/blank-line counting: an IPv6 line preceded by comments and blanks must
// still report the true line number, proving line counting is robust.
func TestLoadCIDRFile_IPv6LineNumberWithCommentsAndBlanks(t *testing.T) {
	cidrFile := filepath.Join(t.TempDir(), "commented.txt")
	// line 1: # header
	// line 2: (blank)
	// line 3: 10.0.0.0/8 (ok)
	// line 4: fe80::/10  (IPv6 -> reject here)
	content := "# header\n\n10.0.0.0/8\nfe80::/10\n"
	if err := os.WriteFile(cidrFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadCIDRFile(cidrFile)
	if err == nil {
		t.Fatal("expected error for IPv6 line, got nil")
	}
	if !strings.Contains(err.Error(), "line 4") {
		t.Fatalf("error does not point at line 4 (IPv6 line after comment+blank): %v", err)
	}
}
