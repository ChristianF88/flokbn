package jail

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestJailToJSONAndBack(t *testing.T) {
	jail := NewJail()
	cidr := "192.168.1.0/24"

	// Add a prisoner to the first cell
	jail.Fill(cidr)
	jailJSON, err := JailToJSON(jail)
	if err != nil {
		t.Errorf("Error converting jail to JSON: %v", err)
	}
	fmt.Println("Jail JSON:", jailJSON)
	var jailFromJSON Jail
	jailFromJSON, err = JSONToJail(jailJSON)
	if err != nil {
		t.Errorf("Error converting JSON to jail: %v", err)
	}

	if !jailsAreEqual(jail, jailFromJSON) {
		t.Errorf("Expected jail to be equal after JSON conversion, got different values")
	}

}

func TestJailToFile(t *testing.T) {
	tmpDir := t.TempDir()
	jail := NewJail()
	cidr := "192.168.1.0/24"
	filename := tmpDir + string(os.PathSeparator) + "test_jail.json"

	// Add a prisoner to the first cell
	jail.Fill(cidr)

	// Write the jail to a file
	err := JailToFile(jail, filename)
	if err != nil {
		t.Errorf("Error writing jail to file: %v", err)
	}

	// Read the jail back from the file
	jailFromFile, err := FileToJail(filename)
	if err != nil {
		t.Errorf("Error reading jail from file: %v", err)
	}

	// Compare the original jail with the one read from the file
	if !jailsAreEqual(jail, jailFromFile) {
		t.Errorf("Expected jail to be equal after file write and read, got different values")
	}

	// No manual cleanup needed - t.TempDir() handles it automatically
}

func TestWriteBanFile(t *testing.T) {
	tmpDir := t.TempDir()
	filename := tmpDir + string(os.PathSeparator) + "test_write_ban_file.txt"

	// CIDRs to write to the file
	cidrs := []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"}

	// Write the CIDRs to the file using WriteBanFile
	err := WriteBanFile(filename, cidrs)
	if err != nil {
		t.Fatalf("Error writing CIDRs to file: %v", err)
	}

	// Read the file back to verify its contents
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Error reading file: %v", err)
	}
	fmt.Println("File content:", string(content))

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

// Helper function to compare two Jail structs
func jailsAreEqual(j1, j2 Jail) bool {
	if len(j1.Cells) != len(j2.Cells) {
		return false
	}
	for i := range j1.Cells {
		if j1.Cells[i].BanDuration != j2.Cells[i].BanDuration || len(j1.Cells[i].Prisoners) != len(j2.Cells[i].Prisoners) {
			return false
		}
		for j := range j1.Cells[i].Prisoners {
			p1, p2 := j1.Cells[i].Prisoners[j], j2.Cells[i].Prisoners[j]
			if p1.CIDR != p2.CIDR || p1.BanActive != p2.BanActive || !p1.BanStart.Equal(p2.BanStart) {
				return false
			}
		}
	}
	return true
}
