package jail

import (
	"os"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/config"
)

func TestFillJail_NewPrisoner(t *testing.T) {
	jail := NewJail()
	cidr := "192.168.1.0/24"

	jail.Fill(cidr)

	if len(jail.Cells[0].Prisoners) != 1 {
		t.Errorf("Expected 1 prisoner in the first cell, got %d", len(jail.Cells[0].Prisoners))
	}

	if jail.Cells[0].Prisoners[0].CIDR != cidr {
		t.Errorf("Expected CIDR %s, got %s", cidr, jail.Cells[0].Prisoners[0].CIDR)
	}

	if !jail.Cells[0].Prisoners[0].BanActive {
		t.Errorf("Expected BanActive to be true, got false")
	}
}

func TestFillJail_MovePrisonerToNextCell(t *testing.T) {
	jail := NewJail()
	cidr := "192.168.1.0/24"

	// Add prisoner to the first cell
	jail.Fill(cidr)

	// Simulate ban duration expiration
	jail.Cells[0].Prisoners[0].BanStart = time.Now().Add(-jail.Cells[0].BanDuration - 11*time.Minute)
	jail.Cells[0].Prisoners[0].BanActive = false

	// Move prisoner to the next cell
	jail.Fill(cidr)

	if len(jail.Cells[0].Prisoners) != 0 {
		t.Errorf("Expected 0 prisoners in the first cell, got %d", len(jail.Cells[0].Prisoners))
	}

	if len(jail.Cells[1].Prisoners) != 1 {
		t.Errorf("Expected 1 prisoner in the second cell, got %d", len(jail.Cells[1].Prisoners))
	}

	if jail.Cells[1].Prisoners[0].CIDR != cidr {
		t.Errorf("Expected CIDR %s in the second cell, got %s", cidr, jail.Cells[1].Prisoners[0].CIDR)
	}
}

func TestFillJail_RenewBanInLastCell(t *testing.T) {
	jail := NewJail()
	cidr := "192.168.1.0/24"

	// Add prisoner to the last cell
	for i := 0; i < len(jail.Cells); i++ {
		jail.Fill(cidr)
		jail.Cells[i].Prisoners[0].BanStart = time.Now().Add(-jail.Cells[i].BanDuration - time.Minute)
		jail.Cells[i].Prisoners[0].BanActive = false
	}

	jail.Fill(cidr)

	lastCellIndex := len(jail.Cells) - 1
	if len(jail.Cells[lastCellIndex].Prisoners) != 1 {
		t.Errorf("Expected 1 prisoner in the last cell, got %d", len(jail.Cells[lastCellIndex].Prisoners))
	}

	if jail.Cells[lastCellIndex].Prisoners[0].CIDR != cidr {
		t.Errorf("Expected CIDR %s in the last cell, got %s", cidr, jail.Cells[lastCellIndex].Prisoners[0].CIDR)
	}

	if !jail.Cells[lastCellIndex].Prisoners[0].BanActive {
		t.Errorf("Expected BanActive to be true in the last cell, got false")
	}
}
func TestUpdateBanActiveStatus(t *testing.T) {
	jail := NewJail()
	cidr := "192.168.1.0/24"

	// Add a prisoner to the first cell
	jail.Fill(cidr)

	// Simulate ban duration expiration
	jail.Cells[0].Prisoners[0].BanStart = time.Now().Add(-jail.Cells[0].BanDuration - time.Minute)
	jail.Cells[0].Prisoners[0].BanActive = false

	// Update ban active status
	jail.UpdateBanActiveStatus()

	if jail.Cells[0].Prisoners[0].BanActive {
		t.Errorf("Expected BanActive to be false, got true")
	}

	// Add another prisoner with an active ban
	cidr2 := "192.168.2.0/24"
	jail.Fill(cidr2)

	// Ensure the second prisoner's ban is still active
	jail.UpdateBanActiveStatus()

	if !jail.Cells[0].Prisoners[1].BanActive {
		t.Errorf("Expected BanActive to be true, got false")
	}
}
func TestInitJail_FileExists(t *testing.T) {
	// Mock the config.JailFile path
	config.JailFile = "test_jail_file.json"

	// Create a mock jail file
	mockJail := NewJail()
	mockJail.Fill(
		"192.218.1.0/24",
	)
	err := JailToFile(mockJail, config.JailFile)
	if err != nil {
		t.Fatalf("Failed to create mock jail file: %v", err)
	}
	defer os.Remove(config.JailFile) // Clean up after test

	// Verify the jail was loaded from the file
	if len(mockJail.Cells) == 0 {
		t.Errorf("Expected jail to be loaded from file, got 0 cells")
	}
}

func TestActiveBansFromJail_NoPrisoners(t *testing.T) {
	jail := NewJail()
	activeBans := jail.ListActiveBans()
	if len(activeBans) != 0 {
		t.Errorf("Expected 0 active bans, got %d", len(activeBans))
	}
}

func TestActiveBansFromJail_SingleActiveBan(t *testing.T) {
	jail := NewJail()
	cidr := "10.0.0.0/24"
	jail.Fill(cidr)
	activeBans := jail.ListActiveBans()
	if len(activeBans) != 1 {
		t.Errorf("Expected 1 active ban, got %d", len(activeBans))
	}
	if activeBans[0] != cidr {
		t.Errorf("Expected CIDR %s, got %s", cidr, activeBans[0])
	}
}

func TestActiveBansFromJail_MultipleActiveBans(t *testing.T) {
	jail := NewJail()
	cidr1 := "10.0.0.0/24"
	cidr2 := "192.168.0.0/24"
	jail.Fill(cidr1)
	jail.Fill(cidr2)
	activeBans := jail.ListActiveBans()
	if len(activeBans) != 2 {
		t.Errorf("Expected 2 active bans, got %d", len(activeBans))
	}
	found1, found2 := false, false
	for _, cidr := range activeBans {
		if cidr == cidr1 {
			found1 = true
		}
		if cidr == cidr2 {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Errorf("Expected to find both CIDRs in active bans")
	}
}

func TestActiveBansFromJail_ExpiredBan(t *testing.T) {
	jail := NewJail()
	cidr := "172.16.0.0/16"
	jail.Fill(cidr)
	// Expire the ban
	jail.Cells[0].Prisoners[0].BanStart = time.Now().Add(-jail.Cells[0].BanDuration - time.Minute)
	jail.Cells[0].Prisoners[0].BanActive = false
	activeBans := jail.ListActiveBans()
	if len(activeBans) != 0 {
		t.Errorf("Expected 0 active bans after expiration, got %d", len(activeBans))
	}
}

func TestActiveBansFromJail_MixedActiveAndInactive(t *testing.T) {
	jail := NewJail()
	cidrActive := "8.8.8.0/24"
	cidrInactive := "8.8.4.0/24"
	jail.Fill(cidrActive)
	jail.Fill(cidrInactive)
	// Expire the second ban
	jail.Cells[0].Prisoners[1].BanStart = time.Now().Add(-jail.Cells[0].BanDuration - time.Minute)
	jail.Cells[0].Prisoners[1].BanActive = false
	activeBans := jail.ListActiveBans()
	if len(activeBans) != 1 {
		t.Errorf("Expected 1 active ban, got %d", len(activeBans))
	}
	if activeBans[0] != cidrActive {
		t.Errorf("Expected CIDR %s, got %s", cidrActive, activeBans[0])
	}
}

func TestFill_NewPrisonerAdded(t *testing.T) {
	jail := NewJail()
	cidr := "192.168.100.0/24"
	jail.Fill(cidr)
	if len(jail.Cells[0].Prisoners) != 1 {
		t.Errorf("Expected 1 prisoner in first cell, got %d", len(jail.Cells[0].Prisoners))
	}
	if jail.Cells[0].Prisoners[0].CIDR != cidr {
		t.Errorf("Expected prisoner CIDR %s, got %s", cidr, jail.Cells[0].Prisoners[0].CIDR)
	}
	if !jail.Cells[0].Prisoners[0].BanActive {
		t.Errorf("Expected BanActive true, got false")
	}
	if len(jail.AllCIDRs) != 1 || jail.AllCIDRs[0] != cidr {
		t.Errorf("Expected AllCidrs to contain %s", cidr)
	}
}

func TestFill_ExistingPrisonerBanExpired_MovesToNextCell(t *testing.T) {
	jail := NewJail()
	cidr := "10.10.10.0/24"
	jail.Fill(cidr)
	// Simulate ban expired
	jail.Cells[0].Prisoners[0].BanStart = time.Now().Add(-jail.Cells[0].BanDuration - time.Minute)
	jail.Cells[0].Prisoners[0].BanActive = false
	jail.Fill(cidr)
	if len(jail.Cells[0].Prisoners) != 0 {
		t.Errorf("Expected 0 prisoners in first cell after move, got %d", len(jail.Cells[0].Prisoners))
	}
	if len(jail.Cells[1].Prisoners) != 1 {
		t.Errorf("Expected 1 prisoner in second cell, got %d", len(jail.Cells[1].Prisoners))
	}
	if jail.Cells[1].Prisoners[0].CIDR != cidr {
		t.Errorf("Expected CIDR %s in second cell, got %s", cidr, jail.Cells[1].Prisoners[0].CIDR)
	}
}

func TestFill_InvalidCIDR_DoesNotPanic(t *testing.T) {
	jail := NewJail()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Fill panicked on invalid CIDR: %v", r)
		}
	}()
	err := jail.Fill("invalid-cidr")
	if err == nil {
		t.Errorf("Expected error for invalid CIDR, got nil")
	}
	// Should not add to jail
	for _, cell := range jail.Cells {
		for _, prisoner := range cell.Prisoners {
			if prisoner.CIDR == "invalid-cidr" {
				t.Errorf("Expected invalid CIDR not to be added, but found in jail")
			}
		}
	}
}

// TestCidrBounds_RejectsIPv6 is the URGENT-21 repro for cidrBounds. Plain IPv6
// CIDRs were already rejected (To4()==nil), but IPv4-mapped IPv6 such as
// "::ffff:192.168.1.0/120" has a non-nil To4() and used to slip past the To4()
// guard, then BigEndian.Uint32 misread its 16-byte mask. The mask-length guard
// rejects every IPv6 form while IPv4 CIDRs still parse to correct bounds.
func TestCidrBounds_RejectsIPv6(t *testing.T) {
	rejected := []string{
		"::1/128",
		"2001:db8::/32",
		"::/0",
		"fe80::/10",
		"::ffff:192.168.1.0/120", // IPv4-mapped IPv6 — the closed hole
		"::ffff:1.2.3.4/128",
	}
	for _, cidr := range rejected {
		if _, _, ok := cidrBounds(cidr); ok {
			t.Errorf("cidrBounds(%q) ok = true; want false (IPv6 must be rejected)", cidr)
		}
	}

	// IPv4 CIDRs must still parse to correct inclusive bounds (no regression).
	ipv4 := []struct {
		cidr             string
		wantStart, wantE uint32
	}{
		{"192.168.1.0/24", 0xC0A80100, 0xC0A801FF},
		{"10.0.0.0/8", 0x0A000000, 0x0AFFFFFF},
		{"192.168.1.100/32", 0xC0A80164, 0xC0A80164},
	}
	for _, tc := range ipv4 {
		s, e, ok := cidrBounds(tc.cidr)
		if !ok {
			t.Errorf("cidrBounds(%q) ok = false; want true (valid IPv4)", tc.cidr)
			continue
		}
		if s != tc.wantStart || e != tc.wantE {
			t.Errorf("cidrBounds(%q) = (%#x,%#x); want (%#x,%#x)", tc.cidr, s, e, tc.wantStart, tc.wantE)
		}
	}
}

func TestIsSubRange(t *testing.T) {
	tests := []struct {
		cidr1    string
		cidr2    string
		expected bool
	}{
		// cidr1 is a subrange of cidr2
		{"192.168.1.0/25", "192.168.1.0/24", true},
		{"10.0.0.128/25", "10.0.0.0/24", true},
		{"10.0.0.0/24", "10.0.0.0/16", true},
		// cidr1 is equal to cidr2
		{"192.168.1.0/24", "192.168.1.0/24", true},
		// cidr1 is not a subrange of cidr2
		{"192.168.2.0/24", "192.168.1.0/24", false},
		{"10.0.1.0/24", "10.0.0.0/24", false},
		// cidr1 is larger than cidr2
		{"192.168.1.0/24", "192.168.1.0/25", false},
		// invalid CIDRs
		{"invalid", "192.168.1.0/24", false},
		{"192.168.1.0/24", "invalid", false},
		{"invalid", "invalid", false},
		// IPv6 CIDRs should not panic, just return false
		{"::1/128", "::0/0", false},
		{"2001:db8::/32", "2001:db8::/16", false},
		{"::1/128", "192.168.1.0/24", false},
	}

	// isSubRange was removed as dead code; its sub-range comparison is
	// expressed directly via cidrBounds here.
	isSubRange := func(cidr1, cidr2 string) bool {
		s1, e1, ok1 := cidrBounds(cidr1)
		s2, e2, ok2 := cidrBounds(cidr2)
		if !ok1 || !ok2 {
			return false
		}
		return s1 >= s2 && e1 <= e2
	}

	for _, tt := range tests {
		result := isSubRange(tt.cidr1, tt.cidr2)
		if result != tt.expected {
			t.Errorf("isSubRange(%q, %q) = %v; want %v", tt.cidr1, tt.cidr2, result, tt.expected)
		}
	}
}
func TestFill_AddsNewPrisonerToFirstCell(t *testing.T) {
	jail := NewJail()
	cidr := "192.0.2.0/24"
	jail.Fill(cidr)

	if len(jail.Cells[0].Prisoners) != 1 {
		t.Errorf("Expected 1 prisoner in first cell, got %d", len(jail.Cells[0].Prisoners))
	}
	if jail.Cells[0].Prisoners[0].CIDR != cidr {
		t.Errorf("Expected prisoner CIDR %s, got %s", cidr, jail.Cells[0].Prisoners[0].CIDR)
	}
	if !jail.Cells[0].Prisoners[0].BanActive {
		t.Errorf("Expected BanActive true, got false")
	}
	if len(jail.AllCIDRs) != 1 || jail.AllCIDRs[0] != cidr {
		t.Errorf("Expected AllCidrs to contain %s", cidr)
	}
}

func TestFill_DoesNotAddInvalidCIDR(t *testing.T) {
	jail := NewJail()
	err := jail.Fill("invalid-cidr")
	if err == nil {
		t.Errorf("Expected error for invalid CIDR, got nil")
	}
	for _, cell := range jail.Cells {
		for _, prisoner := range cell.Prisoners {
			if prisoner.CIDR == "invalid-cidr" {
				t.Errorf("Expected invalid CIDR not to be added, but found in jail")
			}
		}
	}
}

func TestFill_MovesPrisonerToNextCellOnRepeatOffense(t *testing.T) {
	jail := NewJail()
	cidr := "203.0.113.0/24"
	jail.Fill(cidr)
	// Simulate ban expired
	jail.Cells[0].Prisoners[0].BanStart = time.Now().Add(-jail.Cells[0].BanDuration - time.Minute)
	jail.Cells[0].Prisoners[0].BanActive = false
	jail.Fill(cidr)
	if len(jail.Cells[0].Prisoners) != 0 {
		t.Errorf("Expected 0 prisoners in first cell after move, got %d", len(jail.Cells[0].Prisoners))
	}
	if len(jail.Cells[1].Prisoners) != 1 {
		t.Errorf("Expected 1 prisoner in second cell, got %d", len(jail.Cells[1].Prisoners))
	}
	if jail.Cells[1].Prisoners[0].CIDR != cidr {
		t.Errorf("Expected CIDR %s in second cell, got %s", cidr, jail.Cells[1].Prisoners[0].CIDR)
	}
}

func TestFill_SubRangeHandling(t *testing.T) {
	jail := NewJail()
	parent := "10.0.0.0/24"
	sub := "10.0.0.128/25"
	jail.Fill(sub)
	// Simulate ban expired for sub
	jail.Cells[0].Prisoners[0].BanStart = time.Now().Add(-jail.Cells[0].BanDuration - time.Minute)
	jail.Cells[0].Prisoners[0].BanActive = false
	jail.Fill(parent)
	// The sub-range was expired, so the parent that absorbs it escalates to the
	// next cell (cell 1); the sub-range must be removed entirely. (Before the
	// URGENT-04 fix the parent incorrectly landed back in cell 0.)
	if cidrExistsInJail(jail, sub) {
		t.Errorf("Expected sub CIDR %s to be removed from jail", sub)
	}
	if !cidrExistsInJail(jail, parent) {
		t.Errorf("Expected parent CIDR %s in jail", parent)
	}
	if got := findCellIndex(jail, parent); got != 1 {
		t.Errorf("Expected parent CIDR %s to escalate to cell 1, got cell %d", parent, got)
	}
}

func TestFill_DoesNotDuplicatePrisoner(t *testing.T) {
	jail := NewJail()
	cidr := "198.51.100.0/24"
	jail.Fill(cidr)
	jail.Fill(cidr)
	count := 0
	for _, cell := range jail.Cells {
		for _, prisoner := range cell.Prisoners {
			if prisoner.CIDR == cidr {
				count++
			}
		}
	}
	if count != 1 {
		t.Errorf("Expected prisoner to appear only once, got %d", count)
	}
}

func cidrExistsInJail(jail Jail, cidr string) bool {
	for _, cell := range jail.Cells {
		for _, prisoner := range cell.Prisoners {
			if prisoner.CIDR == cidr {
				return true
			}
		}
	}
	return false
}

func findCellIndex(jail Jail, cidr string) int {
	for idx, cell := range jail.Cells {
		for _, prisoner := range cell.Prisoners {
			if prisoner.CIDR == cidr {
				return idx
			}
		}
	}
	return -1
}

func TestJail_Fill_Behaviors(t *testing.T) {
	jail := NewJail()

	parent := "10.0.0.0/24"
	sub1 := "10.0.0.0/25"
	sub2 := "10.0.0.128/25"
	unrelated := "192.168.1.0/24"

	// 1. Add subrange 1
	jail.Fill(sub1)
	if !cidrExistsInJail(jail, sub1) {
		t.Errorf("Expected %s to be added to jail", sub1)
	}

	// 2. Add subrange 2
	jail.Fill(sub2)
	if !cidrExistsInJail(jail, sub2) {
		t.Errorf("Expected %s to be added to jail", sub2)
	}

	// Simulate expired bans
	for i := range jail.Cells {
		for j := range jail.Cells[i].Prisoners {
			jail.Cells[i].Prisoners[j].BanStart = time.Now().Add(-jail.Cells[i].BanDuration - time.Minute)
			jail.Cells[i].Prisoners[j].BanActive = false
		}
	}

	// 3. Add parent -> should replace sub1 and sub2
	jail.Fill(parent)

	if !cidrExistsInJail(jail, parent) {
		t.Errorf("Expected %s to be added to jail", parent)
	}
	if cidrExistsInJail(jail, sub1) || cidrExistsInJail(jail, sub2) {
		t.Errorf("Expected subranges %s and %s to be removed from jail", sub1, sub2)
	}

	// 4. Re-add parent -> should move it to next cell
	before := findCellIndex(jail, parent)
	jail.Cells[before].Prisoners[0].BanActive = false
	jail.Fill(parent)
	after := findCellIndex(jail, parent)
	if after != before+1 {
		t.Errorf("Expected %s to move from cell %d to %d", parent, before, after)
	}

	// 5. Add a range that is subrange of parent
	jail.Fill(sub1)
	// parent should not move again
	newCell := findCellIndex(jail, parent)
	if newCell != after {
		t.Errorf("Expected %s to stay in cell %d, but moved to %d", parent, after, newCell)
	}

	// 6. Add completely unrelated range
	jail.Fill(unrelated)
	if !cidrExistsInJail(jail, unrelated) {
		t.Errorf("Expected unrelated range %s to be added to jail", unrelated)
	}
}

func TestJail_FullProgression(t *testing.T) {
	j := NewJail()
	cidr := "10.20.30.0/24"
	numCells := len(j.Cells)

	// Fill the first cell
	if err := j.Fill(cidr); err != nil {
		t.Fatalf("Fill failed on initial insert: %v", err)
	}

	// Progress through cells 0..3 by expiring each ban and calling Fill again
	for i := 0; i < numCells-1; i++ {
		cellIdx := findCellIndex(j, cidr)
		if cellIdx != i {
			t.Fatalf("Expected prisoner in cell %d, found in cell %d", i, cellIdx)
		}

		// Expire the ban in current cell
		j.Cells[i].Prisoners[0].BanStart = time.Now().Add(-j.Cells[i].BanDuration - time.Minute)
		j.Cells[i].Prisoners[0].BanActive = false

		// Fill again to move to next cell
		if err := j.Fill(cidr); err != nil {
			t.Fatalf("Fill failed moving from cell %d to %d: %v", i, i+1, err)
		}
	}

	// Verify prisoner is now in the last cell (index 4)
	lastIdx := numCells - 1
	cellIdx := findCellIndex(j, cidr)
	if cellIdx != lastIdx {
		t.Errorf("Expected prisoner in last cell %d, found in cell %d", lastIdx, cellIdx)
	}

	// Verify the last cell's ban duration is 180 days (4320 hours)
	expectedDuration := 180 * 24 * time.Hour
	if j.Cells[lastIdx].BanDuration != expectedDuration {
		t.Errorf("Expected last cell ban duration %v, got %v", expectedDuration, j.Cells[lastIdx].BanDuration)
	}

	// Expire the ban in the last cell and Fill again -- should stay in last cell
	j.Cells[lastIdx].Prisoners[0].BanStart = time.Now().Add(-j.Cells[lastIdx].BanDuration - time.Minute)
	j.Cells[lastIdx].Prisoners[0].BanActive = false

	if err := j.Fill(cidr); err != nil {
		t.Fatalf("Fill failed when renewing ban in last cell: %v", err)
	}

	// Prisoner must still be in the last cell with an active ban
	cellIdx = findCellIndex(j, cidr)
	if cellIdx != lastIdx {
		t.Errorf("Expected prisoner to stay in last cell %d after renewal, found in cell %d", lastIdx, cellIdx)
	}

	if !j.Cells[lastIdx].Prisoners[0].BanActive {
		t.Errorf("Expected BanActive to be true after renewal in last cell")
	}

	// Ensure prisoner exists exactly once across all cells
	count := 0
	for _, cell := range j.Cells {
		for _, p := range cell.Prisoners {
			if p.CIDR == cidr {
				count++
			}
		}
	}
	if count != 1 {
		t.Errorf("Expected prisoner to appear exactly once, found %d times", count)
	}
}

// TestFill_ParentAbsorbsExpiredSubRanges_Escalates is the URGENT-04 regression:
// a parent CIDR that absorbs ONLY expired sub-ranges must escalate to the next
// cell (maxCellIdx+1), not land back in the deepest sub-range cell. Before the
// fix the inverted `banActive := true` initializer made the escalation branch
// dead and the parent re-landed in cell 0.
func TestFill_ParentAbsorbsExpiredSubRanges_Escalates(t *testing.T) {
	j := NewJail()
	sub1 := "10.0.0.0/25"
	sub2 := "10.0.0.128/25"
	parent := "10.0.0.0/24"

	// Both sub-ranges land in cell 0.
	if err := j.Fill(sub1); err != nil {
		t.Fatalf("Fill(%s): %v", sub1, err)
	}
	if err := j.Fill(sub2); err != nil {
		t.Fatalf("Fill(%s): %v", sub2, err)
	}
	if findCellIndex(j, sub1) != 0 || findCellIndex(j, sub2) != 0 {
		t.Fatalf("expected both sub-ranges in cell 0")
	}

	// Expire BOTH sub-ranges.
	for ci := range j.Cells {
		for pi := range j.Cells[ci].Prisoners {
			j.Cells[ci].Prisoners[pi].BanStart = time.Now().Add(-j.Cells[ci].BanDuration - time.Minute)
			j.Cells[ci].Prisoners[pi].BanActive = false
		}
	}

	// Fill the parent: it absorbs only expired sub-ranges, so it must escalate.
	if err := j.Fill(parent); err != nil {
		t.Fatalf("Fill(%s): %v", parent, err)
	}

	if findCellIndex(j, sub1) != -1 || findCellIndex(j, sub2) != -1 {
		t.Errorf("expected sub-ranges to be removed after parent absorbed them")
	}
	got := findCellIndex(j, parent)
	if got != 1 {
		t.Errorf("expected parent %s to escalate to cell 1, got cell %d", parent, got)
	}
	pi := -1
	for i, p := range j.Cells[got].Prisoners {
		if p.CIDR == parent {
			pi = i
			break
		}
	}
	if pi == -1 || !j.Cells[got].Prisoners[pi].BanActive {
		t.Errorf("expected escalated parent to have an active ban")
	}
}

// TestFill_ParentAbsorbsActiveSubRange_NoEscalation_PreservesProgress verifies
// that when at least one absorbed sub-range is still active, the parent stays in
// the deepest cell (maxCellIdx) AND inherits that active sub-range's BanStart
// (progress preserved, not reset to ~now).
func TestFill_ParentAbsorbsActiveSubRange_NoEscalation_PreservesProgress(t *testing.T) {
	j := NewJail()
	sub1 := "10.0.0.0/25"
	sub2 := "10.0.0.128/25"
	parent := "10.0.0.0/24"

	if err := j.Fill(sub1); err != nil {
		t.Fatalf("Fill(%s): %v", sub1, err)
	}
	if err := j.Fill(sub2); err != nil {
		t.Fatalf("Fill(%s): %v", sub2, err)
	}

	// Expire sub1, leave sub2 active with a distinct, older-than-now BanStart so
	// we can detect whether it is carried (preserved) or reset to time.Now().
	carried := time.Now().Add(-3 * time.Minute).Truncate(time.Millisecond)
	for ci := range j.Cells {
		for pi := range j.Cells[ci].Prisoners {
			switch j.Cells[ci].Prisoners[pi].CIDR {
			case sub1:
				j.Cells[ci].Prisoners[pi].BanStart = time.Now().Add(-j.Cells[ci].BanDuration - time.Minute)
				j.Cells[ci].Prisoners[pi].BanActive = false
			case sub2:
				j.Cells[ci].Prisoners[pi].BanStart = carried
				j.Cells[ci].Prisoners[pi].BanActive = true
			}
		}
	}

	if err := j.Fill(parent); err != nil {
		t.Fatalf("Fill(%s): %v", parent, err)
	}

	got := findCellIndex(j, parent)
	if got != 0 {
		t.Errorf("expected parent %s to stay in cell 0 (active sub-range present), got cell %d", parent, got)
	}
	if findCellIndex(j, sub1) != -1 || findCellIndex(j, sub2) != -1 {
		t.Errorf("expected sub-ranges to be removed after parent absorbed them")
	}
	pi := -1
	for i, p := range j.Cells[got].Prisoners {
		if p.CIDR == parent {
			pi = i
			break
		}
	}
	if pi == -1 {
		t.Fatalf("expected parent %s present in cell 0", parent)
	}
	if !j.Cells[got].Prisoners[pi].BanStart.Equal(carried) {
		t.Errorf("expected parent BanStart preserved as %v, got %v (progress reset)", carried, j.Cells[got].Prisoners[pi].BanStart)
	}
	if !j.Cells[got].Prisoners[pi].BanActive {
		t.Errorf("expected parent ban active")
	}
}

// TestFill_ParentEscalationCapsAtLastCell verifies the escalation cannot
// overflow past the last cell: a sub-range driven to the last cell, expired,
// then absorbed by its parent leaves the parent in the last cell.
func TestFill_ParentEscalationCapsAtLastCell(t *testing.T) {
	j := NewJail()
	sub := "10.0.0.128/25"
	parent := "10.0.0.0/24"
	lastIdx := len(j.Cells) - 1

	// Drive the sub-range up to the last cell via repeat offenses.
	if err := j.Fill(sub); err != nil {
		t.Fatalf("Fill(%s): %v", sub, err)
	}
	for findCellIndex(j, sub) < lastIdx {
		ci := findCellIndex(j, sub)
		for pi := range j.Cells[ci].Prisoners {
			if j.Cells[ci].Prisoners[pi].CIDR == sub {
				j.Cells[ci].Prisoners[pi].BanStart = time.Now().Add(-j.Cells[ci].BanDuration - time.Minute)
				j.Cells[ci].Prisoners[pi].BanActive = false
			}
		}
		if err := j.Fill(sub); err != nil {
			t.Fatalf("Fill(%s) during escalation: %v", sub, err)
		}
	}
	if findCellIndex(j, sub) != lastIdx {
		t.Fatalf("setup: expected sub-range in last cell %d, got %d", lastIdx, findCellIndex(j, sub))
	}

	// Expire the sub-range in the last cell, then absorb it with the parent.
	for pi := range j.Cells[lastIdx].Prisoners {
		if j.Cells[lastIdx].Prisoners[pi].CIDR == sub {
			j.Cells[lastIdx].Prisoners[pi].BanStart = time.Now().Add(-j.Cells[lastIdx].BanDuration - time.Minute)
			j.Cells[lastIdx].Prisoners[pi].BanActive = false
		}
	}
	if err := j.Fill(parent); err != nil {
		t.Fatalf("Fill(%s): %v", parent, err)
	}

	got := findCellIndex(j, parent)
	if got != lastIdx {
		t.Errorf("expected parent %s to stay capped in last cell %d, got cell %d", parent, lastIdx, got)
	}
	if findCellIndex(j, sub) != -1 {
		t.Errorf("expected sub-range removed after parent absorbed it")
	}
}

func TestJail_PersistenceRoundTrip(t *testing.T) {
	j := NewJail()

	cidrs := []string{
		"10.0.0.0/24",
		"172.16.0.0/16",
		"192.168.1.0/24",
		"203.0.113.0/24",
	}

	// Add all CIDRs to cell 0
	for _, cidr := range cidrs {
		if err := j.Fill(cidr); err != nil {
			t.Fatalf("Fill(%s) failed: %v", cidr, err)
		}
	}

	// Move "172.16.0.0/16" to cell 1
	idx := findCellIndex(j, "172.16.0.0/16")
	for pi, p := range j.Cells[idx].Prisoners {
		if p.CIDR == "172.16.0.0/16" {
			j.Cells[idx].Prisoners[pi].BanStart = time.Now().Add(-j.Cells[idx].BanDuration - time.Minute)
			j.Cells[idx].Prisoners[pi].BanActive = false
			break
		}
	}
	j.Fill("172.16.0.0/16")

	// Move "203.0.113.0/24" to cell 2 (two moves)
	for move := 0; move < 2; move++ {
		idx = findCellIndex(j, "203.0.113.0/24")
		for pi, p := range j.Cells[idx].Prisoners {
			if p.CIDR == "203.0.113.0/24" {
				j.Cells[idx].Prisoners[pi].BanStart = time.Now().Add(-j.Cells[idx].BanDuration - time.Minute)
				j.Cells[idx].Prisoners[pi].BanActive = false
				break
			}
		}
		j.Fill("203.0.113.0/24")
	}

	// Verify pre-persistence state
	if findCellIndex(j, "10.0.0.0/24") != 0 {
		t.Fatalf("Expected 10.0.0.0/24 in cell 0")
	}
	if findCellIndex(j, "172.16.0.0/16") != 1 {
		t.Fatalf("Expected 172.16.0.0/16 in cell 1")
	}
	if findCellIndex(j, "203.0.113.0/24") != 2 {
		t.Fatalf("Expected 203.0.113.0/24 in cell 2")
	}
	if findCellIndex(j, "192.168.1.0/24") != 0 {
		t.Fatalf("Expected 192.168.1.0/24 in cell 0")
	}

	// Write to temp file
	tmpDir := t.TempDir()
	filename := tmpDir + string(os.PathSeparator) + "jail_roundtrip.json"

	if err := JailToFile(j, filename); err != nil {
		t.Fatalf("JailToFile failed: %v", err)
	}

	// Read back
	loaded, err := FileToJail(filename)
	if err != nil {
		t.Fatalf("FileToJail failed: %v", err)
	}

	// Compare using the existing helper from io_test.go
	if !jailsAreEqual(j, loaded) {
		t.Errorf("Loaded jail does not match original after round-trip persistence")
	}
}

// TestFillManyDistinctConsistency exercises the cached-bounds Fill path at the
// scale that used to be pathological: many distinct /32s plus a parent /16 that
// must absorb its children. It asserts the merge semantics still hold (the /16
// swallows every child /32, leaving one prisoner) and serves as the correctness
// companion to BenchmarkUpdateManyDistinct.
func TestFillManyDistinctConsistency(t *testing.T) {
	const n = 2000
	j := NewJail()

	cidrs := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		cidrs = append(cidrs, fmtCIDR(10, 0, i/256, i%256, 32))
	}
	if err := j.Update(cidrs); err != nil {
		t.Fatalf("Update(%d /32s): %v", n, err)
	}

	total := 0
	for _, cell := range j.Cells {
		total += len(cell.Prisoners)
	}
	if total != n {
		t.Fatalf("after inserting %d distinct /32s, jail holds %d prisoners, want %d", n, total, n)
	}

	// A parent /16 covering all of them must collapse the children into a
	// single prisoner (ParentRange/SubRange merge path, now driven by cached
	// bounds).
	if err := j.Update([]string{"10.0.0.0/16"}); err != nil {
		t.Fatalf("Update parent /16: %v", err)
	}
	total = 0
	for _, cell := range j.Cells {
		total += len(cell.Prisoners)
	}
	if total != 1 {
		t.Fatalf("parent /16 did not absorb children: jail holds %d prisoners, want 1", total)
	}
}

func fmtCIDR(a, b, c, d, bits int) string {
	return itoa(a) + "." + itoa(b) + "." + itoa(c) + "." + itoa(d) + "/" + itoa(bits)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// BenchmarkUpdateManyDistinct guards against the per-prisoner net.ParseCIDR
// storm in the sub/parent range scans: filling many distinct /32s must stay
// dominated by the cheap cached-bound comparisons, not CIDR re-parsing.
func BenchmarkUpdateManyDistinct(b *testing.B) {
	const n = 4000
	cidrs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		cidrs = append(cidrs, fmtCIDR(10, i/256%256, i/256, i%256, 32))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j := NewJail()
		if err := j.Update(cidrs); err != nil {
			b.Fatal(err)
		}
	}
}
