package config

import (
	"slices"
	"sync"
)

// The four [global] list files (whitelist, blacklist, userAgentWhitelist,
// userAgentBlacklist) are read ONCE per Config. The first caller of a
// Load...CIDRs / Load...Patterns method reads the file - in a CLI run that is
// Validate at the barrier - and every later caller gets the same entries: the
// static pipeline, the ban publish step and the live loop work on exactly the
// bytes that were validated, and a run opens each file one time.
//
// Consequences worth knowing:
//   - an edit to a list file is not seen by a Config that already read it
//     (live mode has always loaded its lists once at startup; a static run is
//     one Config per process). Load a new Config to read the files again.
//   - a load error is kept like a result: asking again returns the same error
//     without touching the file.
//   - changing the path in c.Global makes the next call read the new file.

// listFile is the kept result of reading one list file.
type listFile struct {
	loaded  bool
	path    string // the file the result came from
	entries []string
	err     error
}

// listFiles holds the four kept results. The mutex makes the first load safe
// when two goroutines ask at once (the TUI runs the analysis on its own
// goroutine); it also makes a Config non-copyable, which go vet enforces.
type listFiles struct {
	mu          sync.Mutex
	whitelist   listFile
	blacklist   listFile
	uaWhitelist listFile
	uaBlacklist listFile
}

// get returns the entries of the list file at path. It calls load the first
// time and whenever path is not the file read before. The slice is a copy, so
// a caller that appends to or sorts its list cannot change what the next
// caller gets.
func (l *listFiles) get(f *listFile, path string, load func(string) ([]string, error)) ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !f.loaded || f.path != path {
		f.entries, f.err = load(path)
		f.path, f.loaded = path, true
	}
	return slices.Clone(f.entries), f.err
}
