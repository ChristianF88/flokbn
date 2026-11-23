package cli

import (
	"errors"
	"io/fs"
	"os"

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
// The bytes and file mode are exactly those of jail.JailToFile.
func (s *jailFileState) save(j *jail.Jail, path string) (bool, error) {
	data, err := jail.JailToJSON(*j)
	if err != nil {
		return false, err
	}
	if s.valid && data == s.saved && !fileMissing(path) {
		return false, nil
	}
	if err := jail.WriteToFile(path, data); err != nil {
		s.valid = false
		return false, err
	}
	s.saved, s.valid = data, true
	return true, nil
}
