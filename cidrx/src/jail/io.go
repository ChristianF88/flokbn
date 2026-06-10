package jail

import (
	"encoding/json"
	"fmt"
	"os"
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

// WriteToFile writes the given content to a file with the specified filename
func WriteToFile(filename string, content string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		return err
	}
	return nil
}
func ReadFromFile(filename string) (string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func JailToFile(jail Jail, filename string) error {

	jailJSON, err := JailToJSON(jail)
	if err != nil {
		return err
	}
	err = WriteToFile(filename, jailJSON)
	if err != nil {
		return err
	}
	return nil
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
	jail, err := JSONToJail(jailJSON)
	if err != nil {
		return Jail{}, err
	}
	return jail, nil
}

func WriteBanFile(filename string, cidrs []string) error {
	return WriteBanFileWithBlacklist(filename, cidrs, nil)
}

func WriteBanFileWithBlacklist(filename string, cidrs []string, blacklistCIDRs []string) error {
	// Write the cidrs to the file
	// ignore lines that start with '# '
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	var modificationTime string = time.Now().Format("2006-01-02 15:04:05")
	if _, err := file.WriteString(fmt.Sprintf("# This file was generated automatically. Last modification %s \n", modificationTime)); err != nil {
		return err
	}

	// Write active jail bans
	if len(cidrs) > 0 {
		if _, err := file.WriteString("# Active jail bans:\n"); err != nil {
			return err
		}
		for _, cidr := range cidrs {
			if _, err := file.WriteString(cidr + "\n"); err != nil {
				return err
			}
		}
	}

	// Write manual blacklist entries
	if len(blacklistCIDRs) > 0 {
		if _, err := file.WriteString("# Manual blacklist entries:\n"); err != nil {
			return err
		}
		for _, cidr := range blacklistCIDRs {
			if _, err := file.WriteString(cidr + "\n"); err != nil {
				return err
			}
		}
		if _, err := file.WriteString("# End of manual blacklist\n"); err != nil {
			return err
		}
	}

	return nil
}
