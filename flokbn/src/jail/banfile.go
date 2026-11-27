package jail

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The ban file is the list a firewall reads: one CIDR per line, comment lines
// starting with '#'. It holds what is banned now, nothing else: the jail's
// running bans as Jail.BanList joins them, followed by the manual blacklist,
// both after the whitelist was subtracted (cidr.ComposeBanLists).

// BuildBanFileContent renders the ban file: a header with the time of
// writing, the active bans, and the manual blacklist in a section of its own.
func BuildBanFileContent(bans, blacklist []string) string {
	size := 96
	for _, c := range bans {
		size += len(c) + 1
	}
	for _, c := range blacklist {
		size += len(c) + 1
	}
	var sb strings.Builder
	sb.Grow(size + 96)

	sb.WriteString("# This file was generated automatically. Last modification ")
	sb.WriteString(time.Now().Format("2006-01-02 15:04:05"))
	sb.WriteString(" \n")

	if len(bans) > 0 {
		sb.WriteString("# Active jail bans:\n")
		for _, c := range bans {
			sb.WriteString(c)
			sb.WriteByte('\n')
		}
	}
	if len(blacklist) > 0 {
		sb.WriteString("# Manual blacklist entries:\n")
		for _, c := range blacklist {
			sb.WriteString(c)
			sb.WriteByte('\n')
		}
		sb.WriteString("# End of manual blacklist\n")
	}
	return sb.String()
}

// WriteBanFile writes the ban file for the given lists to path, through a
// temporary file and a rename, so a reader never sees a partial file.
func WriteBanFile(path string, bans, blacklist []string) error {
	return WriteFile(path, BuildBanFileContent(bans, blacklist))
}

// WriteFile writes content to path through a temporary file and a rename, so
// a reader never sees a partial file. The file gets mode 0644.
func WriteFile(path, content string) error {
	return writeFileAtomic(path, []byte(content), 0o644)
}

// writeFileAtomic writes data to filename via a temp file in the same
// directory + rename, so readers never observe a partial file.
func writeFileAtomic(filename string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(filename), filepath.Base(filename)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, filename); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
