package jail

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Convert Jail to json with the json package
func JailToJSON(jail Jail) (string, error) {
	jailJSON, err := json.Marshal(jail)
	if err != nil {
		return "", err
	}
	return string(jailJSON), nil
}

func JSONToJail(jailJSON string) (Jail, error) {
	var jail Jail
	err := json.Unmarshal([]byte(jailJSON), &jail)
	if err != nil {
		return Jail{}, err
	}
	return jail, nil
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

// WriteToFile writes the given content to a file with the specified filename
func WriteToFile(filename string, content string) error {
	return writeFileAtomic(filename, []byte(content), 0644)
}
func ReadFromFile(filename string) (string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func JailToFile(jail Jail, filename string) error {
	jailJSON, err := json.Marshal(jail)
	if err != nil {
		return err
	}
	return writeFileAtomic(filename, jailJSON, 0644)
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func FileToJail(filename string) (Jail, error) {
	if !fileExists(filename) {
		return NewJail(), nil
	}

	jailJSON, err := ReadFromFile(filename)
	if err != nil {
		return Jail{}, err
	}
	// An empty or whitespace-only file (e.g. a 0-byte file from a truncated
	// or interrupted write, or a `touch`) is treated the same as a missing
	// file: fall back to a fresh NewJail() rather than failing. JSONToJail
	// would otherwise error on `unexpected end of JSON input`.
	if strings.TrimSpace(jailJSON) == "" {
		return NewJail(), nil
	}
	jail, err := JSONToJail(jailJSON)
	if err != nil {
		return Jail{}, err
	}
	// A file that EXISTS and parses as valid JSON but yields zero cells
	// (e.g. `null`, `{}`, `{"Cells":null}`) is corrupt: loading it would
	// silently destroy the 5-stage escalation ladder. A genuinely missing
	// or empty file is already handled above (fresh NewJail()); here we
	// fail loud.
	if len(jail.Cells) == 0 {
		return Jail{}, fmt.Errorf("jail file %s parsed to zero cells (corrupt/empty content); refusing to load a cell-less jail that would destroy the escalation ladder (delete the file to start fresh)", filename)
	}
	jail.RefreshBounds()
	return jail, nil
}

func WriteBanFile(filename string, cidrs []string) error {
	return WriteBanFileWithBlacklist(filename, cidrs, nil)
}

// BuildBanFileContent renders the ban file body (timestamp header, active
// bans, blacklist section) exactly as WriteBanFileWithBlacklist writes it.
func BuildBanFileContent(cidrs []string, blacklistCIDRs []string) string {
	var sb strings.Builder
	var modificationTime string = time.Now().Format("2006-01-02 15:04:05")
	sb.WriteString(fmt.Sprintf("# This file was generated automatically. Last modification %s \n", modificationTime))

	// Write active jail bans
	if len(cidrs) > 0 {
		sb.WriteString("# Active jail bans:\n")
		for _, cidr := range cidrs {
			sb.WriteString(cidr + "\n")
		}
	}

	// Write manual blacklist entries
	if len(blacklistCIDRs) > 0 {
		sb.WriteString("# Manual blacklist entries:\n")
		for _, cidr := range blacklistCIDRs {
			sb.WriteString(cidr + "\n")
		}
		sb.WriteString("# End of manual blacklist\n")
	}

	return sb.String()
}

func WriteBanFileWithBlacklist(filename string, cidrs []string, blacklistCIDRs []string) error {
	// Build the full file content in memory, then write it atomically so
	// readers (fail2ban, firewall scripts) never observe a partial file.
	return writeFileAtomic(filename, []byte(BuildBanFileContent(cidrs, blacklistCIDRs)), 0644)
}
