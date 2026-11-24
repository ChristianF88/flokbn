package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// listFixture writes the four [global] list files and returns a Config naming
// them, plus the file paths in the order whitelist, blacklist, UA whitelist,
// UA blacklist.
func listFixture(t *testing.T) (*Config, [4]string) {
	t.Helper()
	dir := t.TempDir()
	paths := [4]string{
		filepath.Join(dir, "whitelist.txt"),
		filepath.Join(dir, "blacklist.txt"),
		filepath.Join(dir, "ua_whitelist.txt"),
		filepath.Join(dir, "ua_blacklist.txt"),
	}
	contents := [4]string{
		"10.0.0.0/8\n192.168.1.7\n",
		"203.0.113.0/24\n",
		"GoodBot/1.0\n",
		"EvilBot/6.6\n# comment\nScanner #1\n",
	}
	for i, path := range paths {
		if err := os.WriteFile(path, []byte(contents[i]), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return &Config{Global: &GlobalConfig{
		Whitelist:          paths[0],
		Blacklist:          paths[1],
		UserAgentWhitelist: paths[2],
		UserAgentBlacklist: paths[3],
	}}, paths
}

var listFixtureWant = [4][]string{
	{"10.0.0.0/8", "192.168.1.7/32"},
	{"203.0.113.0/24"},
	{"GoodBot/1.0"},
	{"EvilBot/6.6", "Scanner #1"},
}

func loadAllLists(c *Config) (lists [4][]string, errs [4]error) {
	lists[0], errs[0] = c.LoadWhitelistCIDRs()
	lists[1], errs[1] = c.LoadBlacklistCIDRs()
	lists[2], errs[2] = c.LoadUserAgentWhitelistPatterns()
	lists[3], errs[3] = c.LoadUserAgentBlacklistPatterns()
	return lists, errs
}

// The barrier (Validate) reads the list files; the run that follows must get
// the same entries without opening the files again. Removing the files after
// Validate makes a second read fail, so a successful load proves there was
// none.
func TestListFiles_ReadOncePerConfig(t *testing.T) {
	for _, mode := range []RunMode{StaticMode, LiveMode} {
		cfg, paths := listFixture(t)
		for _, line := range cfg.Validate(mode).msgs {
			if strings.Contains(line, "cannot open") {
				t.Fatalf("Validate could not read a list file: %s", line)
			}
		}
		for _, path := range paths {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}

		lists, errs := loadAllLists(cfg)
		for i := range lists {
			if errs[i] != nil {
				t.Errorf("mode %d list %d: read again after Validate: %v", mode, i, errs[i])
			}
			if !reflect.DeepEqual(lists[i], listFixtureWant[i]) {
				t.Errorf("mode %d list %d = %v, want %v", mode, i, lists[i], listFixtureWant[i])
			}
		}

		// Validate stays idempotent: a second pass reports no list problem
		// although the files are gone.
		first, second := cfg.Validate(mode).Report(), cfg.Validate(mode).Report()
		if first != second {
			t.Errorf("mode %d: Validate is not idempotent:\n%s\nvs\n%s", mode, first, second)
		}
	}
}

// Without a Validate the first load reads the file and later loads reuse it.
func TestListFiles_FirstLoadIsKept(t *testing.T) {
	cfg, paths := listFixture(t)
	if _, errs := loadAllLists(cfg); errs != [4]error{} {
		t.Fatalf("first load: %v", errs)
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("192.0.2.0/24\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	lists, errs := loadAllLists(cfg)
	if errs != [4]error{} {
		t.Fatalf("second load: %v", errs)
	}
	if !reflect.DeepEqual(lists, listFixtureWant) {
		t.Errorf("second load = %v, want the entries of the first read %v", lists, listFixtureWant)
	}
}

// A load error is kept like a result, so the barrier and the run agree even
// if the file appears in between.
func TestListFiles_ErrorIsKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.txt")
	cfg := &Config{Global: &GlobalConfig{Whitelist: path}}
	_, first := cfg.LoadWhitelistCIDRs()
	if first == nil {
		t.Fatal("want an error for a missing file")
	}
	if err := os.WriteFile(path, []byte("10.0.0.0/8\n"), 0644); err != nil {
		t.Fatal(err)
	}
	got, second := cfg.LoadWhitelistCIDRs()
	if second == nil || second.Error() != first.Error() || got != nil {
		t.Errorf("second load = %v, %v; want nil and the first error %v", got, second, first)
	}
}

// Pointing the Config at another file reads that file.
func TestListFiles_PathChangeReads(t *testing.T) {
	cfg, _ := listFixture(t)
	if _, err := cfg.LoadWhitelistCIDRs(); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.txt")
	if err := os.WriteFile(other, []byte("198.51.100.0/24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Global.Whitelist = other
	got, err := cfg.LoadWhitelistCIDRs()
	if err != nil || !reflect.DeepEqual(got, []string{"198.51.100.0/24"}) {
		t.Errorf("after path change = %v, %v; want [198.51.100.0/24]", got, err)
	}
	cfg.Global.Whitelist = ""
	if got, err := cfg.LoadWhitelistCIDRs(); got != nil || err != nil {
		t.Errorf("no whitelist configured = %v, %v; want nil, nil", got, err)
	}
}

// Every caller gets its own slice: appending to or reordering one must not
// change what the next caller reads.
func TestListFiles_CallersGetCopies(t *testing.T) {
	cfg, _ := listFixture(t)
	first, err := cfg.LoadWhitelistCIDRs()
	if err != nil {
		t.Fatal(err)
	}
	first[0] = "0.0.0.0/0"
	_ = append(first[:1], "1.1.1.1/32")
	second, err := cfg.LoadWhitelistCIDRs()
	if err != nil || !reflect.DeepEqual(second, listFixtureWant[0]) {
		t.Errorf("second caller got %v, %v; want %v", second, err, listFixtureWant[0])
	}
}

// The first load is safe when several goroutines ask at once (run with -race).
func TestListFiles_ConcurrentFirstLoad(t *testing.T) {
	cfg, _ := listFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lists, errs := loadAllLists(cfg)
			if errs != [4]error{} || !reflect.DeepEqual(lists, listFixtureWant) {
				t.Errorf("concurrent load = %v, %v", lists, errs)
			}
		}()
	}
	wg.Wait()
}
