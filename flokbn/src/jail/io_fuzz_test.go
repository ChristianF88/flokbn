package jail

import (
	"os"
	"testing"
)

func FuzzJailLoadFromJSON(f *testing.F) {
	// Seed with a valid jail JSON
	validJail := NewJail()
	validJail.Fill("192.168.1.0/24")
	validJail.Fill("10.0.0.0/8")
	validJSON, err := JailToJSON(validJail)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(validJSON))

	// Seed with empty JSON
	f.Add([]byte("{}"))

	// Seed with invalid JSON
	f.Add([]byte("{invalid"))

	// Seed with empty
	f.Add([]byte(""))

	// Seed with null
	f.Add([]byte("null"))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()
		filename := tmpDir + "/fuzz_jail.json"
		if err := os.WriteFile(filename, data, 0644); err != nil {
			return
		}
		// Should not panic — corrupt files should return errors
		FileToJail(filename)
	})
}
