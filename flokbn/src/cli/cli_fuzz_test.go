package cli

import (
	"testing"
)

func FuzzParseFlexibleTime(f *testing.F) {
	// Seed with valid formats
	f.Add("2024-06-01")
	f.Add("2024-06-01 13")
	f.Add("2024-06-01 13:45")
	// Invalid formats
	f.Add("")
	f.Add("not-a-date")
	f.Add("2024/06/01")
	f.Add("2024-06-01 13:45:00")
	// Edge cases
	f.Add("0000-00-00")
	f.Add("9999-12-31 23:59")

	f.Fuzz(func(t *testing.T, s string) {
		// Should not panic
		parseFlexibleTime(s)
	})
}
