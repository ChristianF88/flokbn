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
// ok is false for parse errors or IPv6 (unsupported), exactly as the previous
// isSubRange parsing behaved.
func cidrBounds(cidr string) (start, end uint32, ok bool) {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, false
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

func isSubRange(cidr1, cidr2 string) bool {
	s1, e1, ok1 := cidrBounds(cidr1)
	s2, e2, ok2 := cidrBounds(cidr2)
	if !ok1 || !ok2 {
		return false
	}
	return s1 >= s2 && e1 <= e2
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
		// Check if CIDR is a parent range to 1 or more ranges in jail
		if present {
			maxCellIdx := maxInList(cellIdxs)
			banStart := time.Now()
			banActive := true
			for i := len(cellIdxs) - 1; i >= 0; i-- {
				if cellIdxs[i] == maxCellIdx {
					banActive = banActive || j.Cells[cellIdxs[i]].Prisoners[prisonerIdxs[i]].BanActive
					banStart = j.Cells[cellIdxs[i]].Prisoners[prisonerIdxs[i]].BanStart
				}
				j.RemovePrisoner(cellIdxs[i], prisonerIdxs[i])
			}
			if !banActive {
				idx := maxCellIdx
				if maxCellIdx < len(j.Cells)-1 {
					idx = maxCellIdx + 1
				}
				ThrowPrisonerInCell(j, idx, Prisoner{
					CIDR:      cidr,
					BanStart:  time.Now(),
					BanActive: true,
				})
			} else {
				ThrowPrisonerInCell(j, maxCellIdx, Prisoner{
					CIDR:      cidr,
					BanStart:  banStart,
					BanActive: true,
				})
			}
			j.AllCIDRs = append(j.AllCIDRs, cidr)

		}

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
