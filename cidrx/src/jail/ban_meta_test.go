package jail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// seedJailWithMixedBans builds a jail with one active prisoner in cell 1,
// one active prisoner in cell 2, and one expired (inactive) prisoner.
func seedJailWithMixedBans(now time.Time) Jail {
	j := NewJail()
	j.Cells[0].Prisoners = append(j.Cells[0].Prisoners, Prisoner{
		CIDR:      "10.0.0.0/24",
		BanStart:  now,
		BanActive: true,
	})
	j.Cells[1].Prisoners = append(j.Cells[1].Prisoners, Prisoner{
		CIDR:      "10.1.0.0/24",
		BanStart:  now.Add(-time.Hour),
		BanActive: true,
	})
	// Expired: ban started long before cell 1's 10min duration.
	j.Cells[0].Prisoners = append(j.Cells[0].Prisoners, Prisoner{
		CIDR:      "10.2.0.0/24",
		BanStart:  now.Add(-24 * time.Hour),
		BanActive: true,
	})
	j.AllCIDRs = append(j.AllCIDRs, "10.0.0.0/24", "10.1.0.0/24", "10.2.0.0/24")
	return j
}

func TestListActiveBansWithMeta_MatchesListActiveBans(t *testing.T) {
	now := time.Now()
	j := seedJailWithMixedBans(now)
	j.UpdateBanActiveStatus() // expires 10.2.0.0/24

	plain := j.ListActiveBans()
	meta := j.ListActiveBansWithMeta()
	if len(meta) != len(plain) {
		t.Fatalf("ListActiveBansWithMeta len = %d, ListActiveBans len = %d", len(meta), len(plain))
	}
	for i := range plain {
		if meta[i].CIDR != plain[i] {
			t.Errorf("entry %d: CIDR = %q, want %q (order must match ListActiveBans)", i, meta[i].CIDR, plain[i])
		}
	}
	for _, b := range meta {
		if b.CIDR == "10.2.0.0/24" {
			t.Error("expired ban 10.2.0.0/24 must not be listed after UpdateBanActiveStatus")
		}
	}
}

func TestListActiveBansWithMeta_StageAndExpiry(t *testing.T) {
	now := time.Now()
	j := seedJailWithMixedBans(now)
	j.UpdateBanActiveStatus()

	meta := j.ListActiveBansWithMeta()
	byCIDR := map[string]ActiveBan{}
	for _, b := range meta {
		byCIDR[b.CIDR] = b
	}

	b1, ok := byCIDR["10.0.0.0/24"]
	if !ok {
		t.Fatal("10.0.0.0/24 missing from ListActiveBansWithMeta")
	}
	if b1.Stage != 1 {
		t.Errorf("10.0.0.0/24 Stage = %d, want 1", b1.Stage)
	}
	if want := b1.BanStart.Add(j.Cells[0].BanDuration); !b1.ExpiresAt.Equal(want) {
		t.Errorf("10.0.0.0/24 ExpiresAt = %v, want BanStart+%v = %v", b1.ExpiresAt, j.Cells[0].BanDuration, want)
	}

	b2, ok := byCIDR["10.1.0.0/24"]
	if !ok {
		t.Fatal("10.1.0.0/24 missing from ListActiveBansWithMeta")
	}
	if b2.Stage != 2 {
		t.Errorf("10.1.0.0/24 Stage = %d, want 2", b2.Stage)
	}
	if want := b2.BanStart.Add(j.Cells[1].BanDuration); !b2.ExpiresAt.Equal(want) {
		t.Errorf("10.1.0.0/24 ExpiresAt = %v, want BanStart+%v = %v", b2.ExpiresAt, j.Cells[1].BanDuration, want)
	}
}

// stripHeaderLine drops the first line (timestamp header) so two renderings
// taken at different wall-clock seconds compare equal.
func stripHeaderLine(t *testing.T, content string) string {
	t.Helper()
	nl := strings.IndexByte(content, '\n')
	if nl < 0 {
		t.Fatalf("content has no header line: %q", content)
	}
	return content[nl+1:]
}

func TestBuildBanFileContent_MatchesWrittenFile(t *testing.T) {
	cases := []struct {
		name      string
		cidrs     []string
		blacklist []string
	}{
		{"BansAndBlacklist", []string{"192.168.1.0/24", "10.0.0.0/8"}, []string{"203.0.113.0/24"}},
		{"BansOnly", []string{"192.168.1.0/24"}, nil},
		{"BlacklistOnly", nil, []string{"203.0.113.0/24"}},
		{"Empty", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ban.txt")
			if err := WriteBanFileWithBlacklist(path, tc.cidrs, tc.blacklist); err != nil {
				t.Fatalf("WriteBanFileWithBlacklist: %v", err)
			}
			written, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading ban file: %v", err)
			}
			built := BuildBanFileContent(tc.cidrs, tc.blacklist)

			const headerPrefix = "# This file was generated automatically."
			if !strings.HasPrefix(built, headerPrefix) {
				t.Errorf("BuildBanFileContent missing header prefix, got %q", built)
			}
			if !strings.HasPrefix(string(written), headerPrefix) {
				t.Errorf("written file missing header prefix, got %q", written)
			}
			if got, want := stripHeaderLine(t, string(written)), stripHeaderLine(t, built); got != want {
				t.Errorf("written body = %q, want BuildBanFileContent body %q", got, want)
			}
		})
	}
}
