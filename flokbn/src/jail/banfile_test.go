package jail

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteBanFile(t *testing.T) {
	tmpDir := t.TempDir()
	filename := tmpDir + string(os.PathSeparator) + "test_write_ban_file.txt"

	// CIDRs to write to the file
	cidrs := []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"}

	// Write the CIDRs to the file using WriteBanFile
	err := WriteBanFile(filename, cidrs, nil)
	if err != nil {
		t.Fatalf("Error writing CIDRs to file: %v", err)
	}

	// Read the file back to verify its contents
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Error reading file: %v", err)
	}

	// Expected content
	expectedHeader := "# This file was generated automatically."
	expectedCIDRs := strings.Join(cidrs, "\n") + "\n"

	// Check if the file contains the expected header
	if !strings.Contains(string(content), expectedHeader) {
		t.Errorf("Expected file to contain header: %s", expectedHeader)
	}

	// Check if the file contains the expected CIDRs
	if !strings.Contains(string(content), expectedCIDRs) {
		t.Errorf("Expected file to contain CIDRs: %s", expectedCIDRs)
	}

	// No manual cleanup needed - t.TempDir() handles it automatically
}

func assertNoTempResidue(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading dir %s: %v", dir, err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file %s in %s", e.Name(), dir)
		}
	}
}

func TestWriteFileAtomic_Basics(t *testing.T) {
	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "atomic.txt"

	// Fresh path
	if err := writeFileAtomic(path, []byte("first"), 0644); err != nil {
		t.Fatalf("writeFileAtomic fresh: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}
	if string(content) != "first" {
		t.Errorf("content = %q, want %q", content, "first")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("file mode = %v, want 0644", info.Mode().Perm())
	}

	// Overwrite existing
	if err := writeFileAtomic(path, []byte("second, longer content"), 0644); err != nil {
		t.Fatalf("writeFileAtomic overwrite: %v", err)
	}
	content, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}
	if string(content) != "second, longer content" {
		t.Errorf("content = %q, want %q", content, "second, longer content")
	}
	assertNoTempResidue(t, dir)

	// Failure: nonexistent parent directory
	badPath := dir + string(os.PathSeparator) + "missing-dir" + string(os.PathSeparator) + "f.txt"
	if err := writeFileAtomic(badPath, []byte("x"), 0644); err == nil {
		t.Error("writeFileAtomic into nonexistent dir: want error, got nil")
	}
	assertNoTempResidue(t, dir)
}

// TestWriteBanFile_NoPartialReads asserts that a concurrent reader never
// observes a truncated or interleaved ban file while the writer keeps
// rewriting it (the pre-atomic os.Create implementation failed this).
func TestWriteBanFile_NoPartialReads(t *testing.T) {
	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "ban.txt"

	cidrsA := make([]string, 0, 300)
	cidrsB := make([]string, 0, 300)
	for i := 0; i < 300; i++ {
		cidrsA = append(cidrsA, fmt.Sprintf("10.0.%d.%d/32", i/256, i%256))
		cidrsB = append(cidrsB, fmt.Sprintf("172.16.%d.%d/32", i/256, i%256))
	}
	bodyA := "# Active jail bans:\n" + strings.Join(cidrsA, "\n") + "\n"
	bodyB := "# Active jail bans:\n" + strings.Join(cidrsB, "\n") + "\n"
	const headerPrefix = "# This file was generated automatically."

	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			data, err := os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					continue // before the first write
				}
				t.Errorf("reader: %v", err)
				return
			}
			content := string(data)
			nl := strings.IndexByte(content, '\n')
			if nl < 0 || !strings.HasPrefix(content, headerPrefix) {
				t.Errorf("reader: missing/torn header line, got %q", truncateForLog(content))
				return
			}
			body := content[nl+1:]
			if body != bodyA && body != bodyB {
				t.Errorf("reader: partial/interleaved body observed, got %q", truncateForLog(body))
				return
			}
		}
	}()

	for i := 0; i < 200; i++ {
		cidrs := cidrsA
		if i%2 == 1 {
			cidrs = cidrsB
		}
		if err := WriteBanFile(path, cidrs, nil); err != nil {
			t.Fatalf("WriteBanFile iteration %d: %v", i, err)
		}
	}
	close(stop)
	<-readerDone
	assertNoTempResidue(t, dir)
}

func truncateForLog(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

func BenchmarkWriteBanFile(b *testing.B) {
	dir := b.TempDir()
	path := dir + string(os.PathSeparator) + "ban.txt"
	cidrs := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		cidrs = append(cidrs, fmt.Sprintf("10.0.%d.0/24", i))
	}
	blacklist := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		blacklist = append(blacklist, fmt.Sprintf("203.0.%d.0/24", i))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := WriteBanFile(path, cidrs, blacklist); err != nil {
			b.Fatal(err)
		}
	}
}

// stripHeaderLine drops the first line (timestamp header) so two renderings
// taken at different wall-clock seconds compare equal.
func stripHeaderLine(t *testing.T, content string) string {
	t.Helper()
	nl := strings.IndexByte(content, '\n')
	if nl < 0 {
		t.Fatalf("content has no header line: %q", content)
	}
	return content[nl+1:]
}

func TestBuildBanFileContent_MatchesWrittenFile(t *testing.T) {
	cases := []struct {
		name      string
		cidrs     []string
		blacklist []string
	}{
		{"BansAndBlacklist", []string{"192.168.1.0/24", "10.0.0.0/8"}, []string{"203.0.113.0/24"}},
		{"BansOnly", []string{"192.168.1.0/24"}, nil},
		{"BlacklistOnly", nil, []string{"203.0.113.0/24"}},
		{"Empty", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ban.txt")
			if err := WriteBanFile(path, tc.cidrs, tc.blacklist); err != nil {
				t.Fatalf("WriteBanFile: %v", err)
			}
			written, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading ban file: %v", err)
			}
			built := BuildBanFileContent(tc.cidrs, tc.blacklist)

			const headerPrefix = "# This file was generated automatically."
			if !strings.HasPrefix(built, headerPrefix) {
				t.Errorf("BuildBanFileContent missing header prefix, got %q", built)
			}
			if !strings.HasPrefix(string(written), headerPrefix) {
				t.Errorf("written file missing header prefix, got %q", written)
			}
			if got, want := stripHeaderLine(t, string(written)), stripHeaderLine(t, built); got != want {
				t.Errorf("written body = %q, want BuildBanFileContent body %q", got, want)
			}
		})
	}
}
