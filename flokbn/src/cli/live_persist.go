package cli

import (
	"errors"
	"io/fs"
	"os"
	"slices"

	"github.com/ChristianF88/flokbn/jail"
)

// fileMissing reports whether path definitely does not exist. Any other stat
// outcome (present, or an error that says nothing about existence) is "not
// missing", so a permission problem never turns into a rewrite on every tick.
func fileMissing(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, fs.ErrNotExist)
}

// jailFileState remembers the jail JSON last written to disk, so the live
// loop persists the jail only when its content changed instead of doing a
// temp file + fsync + rename on every iteration. Owned by the loop goroutine.
type jailFileState struct {
	saved string // JSON of the last successful write
	valid bool   // false until the first successful write, and after a failed one
}

// save writes the jail to path unless its serialized form equals the last
// successful write and the file is still there. It reports whether it wrote.
// The bytes and file mode are exactly those of jail.Jail.Save.
func (s *jailFileState) save(j *jail.Jail, path string) (bool, error) {
	data := string(j.Encode())
	if s.valid && data == s.saved && !fileMissing(path) {
		return false, nil
	}
	if err := jail.WriteFile(path, data); err != nil {
		s.valid = false
		return false, err
	}
	s.saved, s.valid = data, true
	return true, nil
}

// banFileState remembers which ban lists were last written to disk, so the
// ban file (and its timestamp header) is rewritten only when what it lists
// changed. Owned by the loop goroutine.
type banFileState struct {
	// The lists of the last successful write. They are kept as handed in:
	// the publish step builds new lists every round and never changes one
	// afterwards.
	bans, blacklist []string
	valid           bool // false until the first successful write
}

// save writes the ban file for the given lists unless they equal the last
// successful write and the file is still there. It reports whether it wrote,
// and the content it wrote. Until the first write has succeeded every call
// writes, which syncs a stale ban file left on disk by an earlier run.
//
// A round that changes nothing costs one comparison of the lists and one
// stat; the file content is only built when it is written.
func (s *banFileState) save(bans, blacklist []string, path string) (content string, wrote bool, err error) {
	if s.valid && slices.Equal(bans, s.bans) && slices.Equal(blacklist, s.blacklist) && !fileMissing(path) {
		return "", false, nil
	}
	content = jail.BuildBanFileContent(bans, blacklist)
	if err := jail.WriteFile(path, content); err != nil {
		return "", false, err
	}
	s.bans, s.blacklist, s.valid = bans, blacklist, true
	return content, true, nil
}
