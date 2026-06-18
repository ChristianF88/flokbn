package jail

import (
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"time"
)

type Cell struct {
	ID          int `json:"Id"`
	Description string
	BanDuration time.Duration
	Prisoners   []Prisoner
}

type Prisoner struct {
	CIDR      string `json:"Cidr"`
	BanStart  time.Time
	BanActive bool

	// Cached IPv4 numeric bounds of CIDR, valid iff boundsOK. Unexported, so
	// encoding/json never (de)serializes them. Set eagerly when a prisoner is
	// added (ThrowPrisonerInCell) or loaded (RefreshBounds); the sub/parent
	// range scans read them instead of calling net.ParseCIDR per prisoner.
	startU, endU uint32
	boundsOK     bool
}

type Jail struct {
	Cells    []Cell
	AllCIDRs []string `json:"AllCidrs"` // all ranges currently in jail
}

func (j *Jail) RemovePrisoner(cellIdx, prisonerIdx int) {
	if cellIdx < 0 || cellIdx >= len(j.Cells) {
		return
	}
	if prisonerIdx < 0 || prisonerIdx >= len(j.Cells[cellIdx].Prisoners) {
		return
	}

	// Get CIDR before removal
	cidr := j.Cells[cellIdx].Prisoners[prisonerIdx].CIDR

	// Remove the prisoner from the cell
	j.Cells[cellIdx].Prisoners = append(
		j.Cells[cellIdx].Prisoners[:prisonerIdx],
		j.Cells[cellIdx].Prisoners[prisonerIdx+1:]...,
	)

	// Remove the CIDR from the AllCidrs slice
	for i, cidrInJail := range j.AllCIDRs {
		if cidrInJail == cidr {
			j.AllCIDRs = append(
				j.AllCIDRs[:i],
				j.AllCIDRs[i+1:]...,
			)
			break
		}
	}
}

func NewCell(id int, description string, banDuration time.Duration) Cell {
	return Cell{
		ID:          id,
		Description: description,
		BanDuration: banDuration,
		Prisoners:   []Prisoner{},
	}
}

func NewJail() Jail {
	return Jail{
		Cells: []Cell{
			NewCell(1, "Stage 1 Ban -> 10min", 10*time.Minute),
			NewCell(2, "Stage 2 Ban -> 4h", 4*time.Hour),
			NewCell(3, "Stage 3 Ban -> 7d", 7*24*time.Hour),
			NewCell(4, "Stage 4 Ban -> 30d", 30*24*time.Hour),
			NewCell(5, "Stage 5 Ban -> 180d", 180*24*time.Hour),
		},
		AllCIDRs: []string{},
	}
}

func (j *Jail) rangeInJail(cidr string) (bool, int, int) {
	for cId, cell := range j.Cells {
		for pId, prisoner := range cell.Prisoners {
			if prisoner.CIDR == cidr {
				return true, cId, pId
			}
		}
	}
	return false, -1, -1
}

func BanDurationIsOver(banStart time.Time, banDuration time.Duration) bool {
	return time.Since(banStart) > banDuration
}

func ThrowPrisonerInCell(jail *Jail, cellIndex int, prisoner Prisoner) {
	if cellIndex < 0 || cellIndex >= len(jail.Cells) {
		return
	}
	prisoner.BanStart = time.Now()
	prisoner.BanActive = true
	prisoner.startU, prisoner.endU, prisoner.boundsOK = cidrBounds(prisoner.CIDR)
	jail.Cells[cellIndex].Prisoners = append(
		jail.Cells[cellIndex].Prisoners, prisoner,
	)
}

// RefreshBounds populates each prisoner's cached numeric bounds. Call it after
// loading a jail from disk so the sub/parent range scans avoid re-parsing every
// prisoner CIDR. Prisoners added via ThrowPrisonerInCell already have bounds
// set; this only matters for deserialized jails.
func (j *Jail) RefreshBounds() {
	for ci := range j.Cells {
		for pi := range j.Cells[ci].Prisoners {
			p := &j.Cells[ci].Prisoners[pi]
			p.startU, p.endU, p.boundsOK = cidrBounds(p.CIDR)
		}
	}
}

func MovePrisonerToNextCell(jail *Jail, cellIndex int, prisonerIndex int) {

	jail.Cells[cellIndex].Prisoners[prisonerIndex].BanStart = time.Now()
	jail.Cells[cellIndex].Prisoners[prisonerIndex].BanActive = true

	// If prisoner is not the last in the cell and there is a next cell
	if cellIndex < len(jail.Cells)-1 {

		// Move the prisoner to the next cell
		jail.Cells[cellIndex+1].Prisoners = append(
			jail.Cells[cellIndex+1].Prisoners,
			jail.Cells[cellIndex].Prisoners[prisonerIndex],
		)
		// Remove the prisoner from the current cell
		jail.Cells[cellIndex].Prisoners = append(
			jail.Cells[cellIndex].Prisoners[:prisonerIndex],
			jail.Cells[cellIndex].Prisoners[prisonerIndex+1:]...,
		)
	}
}

// cidrBounds parses an IPv4 CIDR into its inclusive [start,end] numeric range.
// ok is false for parse errors or any IPv6 form (unsupported).
//
// IPv4-only enforcement: gate on the mask length, not To4(). net.ParseCIDR gives
// every IPv6 form a 16-byte mask, including IPv4-mapped IPv6 (::ffff:a.b.c.d/120)
// whose To4() is non-nil but whose mask is still 16 bytes. The mask is 4 bytes
// only for IPv4-notation CIDRs, so len(n.Mask) != 4 rejects every IPv6 form and
// keeps binary.BigEndian.Uint32(n.Mask) from misreading a 16-byte mask.
func cidrBounds(cidr string) (start, end uint32, ok bool) {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, false
	}
	if len(n.Mask) != 4 {
		return 0, 0, false // IPv6 (incl. IPv4-mapped) not supported
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, 0, false // IPv6 not supported
	}
	start = binary.BigEndian.Uint32(v4)
	end = start | ^binary.BigEndian.Uint32(n.Mask)
	return start, end, true
}

// prisonerBounds returns a prisoner's cached numeric range, falling back to
// parsing CIDR if the cache was never populated (e.g. a struct literal built
// outside ThrowPrisonerInCell/RefreshBounds, as in tests). Correctness never
// depends on the cache — only speed.
func prisonerBounds(p Prisoner) (start, end uint32, ok bool) {
	if p.boundsOK {
		return p.startU, p.endU, true
	}
	return cidrBounds(p.CIDR)
}

func (j *Jail) SubRangesInJail(cidr string) (bool, []int, []int) {
	var matchedCells []int
	var matchedPrisoners []int
	found := false

	// Parse the query range once; compare against each prisoner's cached
	// bounds. A prisoner is a sub-range of cidr iff it lies within [qs,qe].
	qs, qe, qok := cidrBounds(cidr)
	if !qok {
		return false, nil, nil
	}
	for cellIdx, cell := range j.Cells {
		for prisonerIdx, prisoner := range cell.Prisoners {
			ps, pe, pok := prisonerBounds(prisoner)
			if pok && ps >= qs && pe <= qe {
				matchedCells = append(matchedCells, cellIdx)
				matchedPrisoners = append(matchedPrisoners, prisonerIdx)
				found = true
			}
		}
	}
	return found, matchedCells, matchedPrisoners
}

func (j *Jail) ParentRangeInJail(cidr string) (bool, int, int) {
	// Parse the query range once; cidr is a sub-range of a prisoner iff
	// [qs,qe] lies within that prisoner's cached bounds.
	qs, qe, qok := cidrBounds(cidr)
	if !qok {
		return false, -1, -1
	}
	for cellIdx, cell := range j.Cells {
		for prisonerIdx, prisoner := range cell.Prisoners {
			ps, pe, pok := prisonerBounds(prisoner)
			if pok && qs >= ps && qe <= pe {
				return true, cellIdx, prisonerIdx
			}
		}
	}
	return false, -1, -1
}

func maxInList(list []int) int {
	if len(list) == 0 {
		return -1
	}
	return slices.Max(list)
}

func (j *Jail) Fill(cidr string) error {
	if cidr == "" {
		return fmt.Errorf("empty CIDR string provided to Fill")
	}

	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("error parsing CIDR %s: %w", cidr, err)
	}

	if inJail, cellIdx, prisonerIdx := j.rangeInJail(cidr); inJail {
		// CIDR already in jail: move prisoner only if current ban is inactive
		if !j.Cells[cellIdx].Prisoners[prisonerIdx].BanActive {
			MovePrisonerToNextCell(j, cellIdx, prisonerIdx)
		}

	} else if present, cellIdxs, prisonerIdxs := j.SubRangesInJail(cidr); present {
		// CIDR is a parent range to 1 or more ranges in jail. Absorb the
		// matched sub-ranges into a single prisoner for the parent.
		maxCellIdx := maxInList(cellIdxs)
		var banStart time.Time
		banActive := false
		for i := len(cellIdxs) - 1; i >= 0; i-- {
			if cellIdxs[i] == maxCellIdx {
				// Track whether any matched sub-range in the deepest cell still
				// has an active ban, and carry its BanStart to preserve progress.
				if j.Cells[cellIdxs[i]].Prisoners[prisonerIdxs[i]].BanActive {
					banActive = true
					banStart = j.Cells[cellIdxs[i]].Prisoners[prisonerIdxs[i]].BanStart
				}
			}
			j.RemovePrisoner(cellIdxs[i], prisonerIdxs[i])
		}
		if !banActive {
			// All matched sub-ranges expired: escalate the parent one cell
			// (capped at the last cell) with a fresh timer, matching the
			// single-prisoner repeat-offense path.
			idx := maxCellIdx
			if maxCellIdx < len(j.Cells)-1 {
				idx = maxCellIdx + 1
			}
			ThrowPrisonerInCell(j, idx, Prisoner{CIDR: cidr})
		} else {
			// At least one matched sub-range is still active: keep the parent in
			// the deepest cell and preserve the carried ban progress. The
			// BanStart write must come after ThrowPrisonerInCell, which would
			// otherwise reset BanStart to time.Now().
			ThrowPrisonerInCell(j, maxCellIdx, Prisoner{CIDR: cidr})
			last := len(j.Cells[maxCellIdx].Prisoners) - 1
			j.Cells[maxCellIdx].Prisoners[last].BanStart = banStart
		}
		j.AllCIDRs = append(j.AllCIDRs, cidr)

	} else if parent, cellIdx, prisonerIdx := j.ParentRangeInJail(cidr); parent {
		// Check if range is a subrange to a range in jail
		if !j.Cells[cellIdx].Prisoners[prisonerIdx].BanActive {
			MovePrisonerToNextCell(j, cellIdx, prisonerIdx)
		}
	} else {
		// If CIDR is not in jail, add it to the first cell
		ThrowPrisonerInCell(j, 0, Prisoner{
			CIDR:      cidr,
			BanStart:  time.Now(),
			BanActive: true,
		})
		j.AllCIDRs = append(j.AllCIDRs, cidr)
	}

	return nil
}

func (j *Jail) UpdateBanActiveStatus() {
	for i := 0; i < len(j.Cells); i++ {
		for k := 0; k < len(j.Cells[i].Prisoners); k++ {
			if BanDurationIsOver(j.Cells[i].Prisoners[k].BanStart, j.Cells[i].BanDuration) {
				j.Cells[i].Prisoners[k].BanActive = false
			}
		}
	}
}

// RetentionHorizon is the escalation-memory window: the span past a prisoner's
// expiry during which a re-detection must still escalate it (Fill -> rangeInJail
// -> MovePrisonerToNextCell relies on the expired-but-resident prisoner). It is
// the LAST cell's BanDuration (the deepest ban window, 180d for the default
// ladder). Pruning only entries stale beyond this window guarantees Prune never
// forgets a prisoner that re-offense escalation still cares about. Returns 0 for
// a jail with no cells.
func (j *Jail) RetentionHorizon() time.Duration {
	if len(j.Cells) == 0 {
		return 0
	}
	return j.Cells[len(j.Cells)-1].BanDuration
}

// Prune evicts prisoners whose ban expired more than horizon ago, bounding the
// jail to active+recent bans instead of lifetime-distinct CIDRs. A prisoner is
// stale iff it is NOT BanActive AND now > BanStart + cellDuration + horizon
// (i.e. time.Since(expiry) > horizon, measured from EXPIRY so escalation memory
// is preserved for the full retention window). Active bans are never evicted.
//
// Single O(total prisoners) pass: each cell's Prisoners slice is compacted in
// place (reusing the backing array, zero allocation on the no-evict path), then
// AllCIDRs is rebuilt ONCE from the survivors so it stays exactly consistent
// (no orphans, no duplicates). RemovePrisoner is deliberately NOT called per
// eviction — that would be O(prisoners) per call (AllCIDRs linear scan) and turn
// Prune into O(prisoners^2). Returns the number of prisoners evicted.
func (j *Jail) Prune(horizon time.Duration) int {
	now := time.Now()
	pruned := 0
	for ci := range j.Cells {
		cell := &j.Cells[ci]
		dur := cell.BanDuration
		keep := cell.Prisoners[:0]
		for _, p := range cell.Prisoners {
			expiry := p.BanStart.Add(dur)
			if !p.BanActive && now.Sub(expiry) > horizon {
				pruned++
				continue
			}
			keep = append(keep, p)
		}
		// Clear the tail so evicted Prisoner structs don't keep their CIDR
		// strings alive in the unused capacity.
		for i := len(keep); i < len(cell.Prisoners); i++ {
			cell.Prisoners[i] = Prisoner{}
		}
		cell.Prisoners = keep
	}
	if pruned == 0 {
		return 0
	}
	// Rebuild AllCIDRs once from survivors so it is exactly the set of resident
	// prisoner CIDRs.
	survivors := 0
	for ci := range j.Cells {
		survivors += len(j.Cells[ci].Prisoners)
	}
	allCIDRs := make([]string, 0, survivors)
	for ci := range j.Cells {
		for _, p := range j.Cells[ci].Prisoners {
			allCIDRs = append(allCIDRs, p.CIDR)
		}
	}
	j.AllCIDRs = allCIDRs
	return pruned
}

func (j *Jail) Update(cidrs []string) error {
	j.UpdateBanActiveStatus()

	var errs []error
	for _, cidr := range cidrs {
		if err := j.Fill(cidr); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("jail update encountered %d errors, first: %w", len(errs), errs[0])
	}
	return nil
}

// retrieve active bans (cidrs) from the jail
func (j *Jail) ListActiveBans() []string {
	cidrs := []string{}
	for _, cell := range j.Cells {
		for _, prisoner := range cell.Prisoners {
			if prisoner.BanActive {
				cidrs = append(cidrs, prisoner.CIDR)
			}
		}
	}
	return cidrs
}

// ActiveBan is a currently-active ban with its escalation metadata.
type ActiveBan struct {
	CIDR      string
	Stage     int // Cell.ID
	BanStart  time.Time
	ExpiresAt time.Time // BanStart.Add(Cell.BanDuration)
}

// ListActiveBansWithMeta returns one entry per BanActive prisoner, in the
// same cell/prisoner iteration order as ListActiveBans. Like the ban file,
// it trusts the BanActive flags refreshed by UpdateBanActiveStatus: a ban
// expiring between updates still reads as active until the next Update.
func (j *Jail) ListActiveBansWithMeta() []ActiveBan {
	bans := []ActiveBan{}
	for _, cell := range j.Cells {
		for _, prisoner := range cell.Prisoners {
			if prisoner.BanActive {
				bans = append(bans, ActiveBan{
					CIDR:      prisoner.CIDR,
					Stage:     cell.ID,
					BanStart:  prisoner.BanStart,
					ExpiresAt: prisoner.BanStart.Add(cell.BanDuration),
				})
			}
		}
	}
	return bans
}
