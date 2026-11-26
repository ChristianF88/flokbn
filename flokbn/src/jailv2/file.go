package jailv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/ChristianF88/flokbn/cidr"
	"github.com/ChristianF88/flokbn/iputils"
	"github.com/ChristianF88/flokbn/jail"
)

// fileVersion marks the file format of this package. The format of package
// jail carries no version; Decode recognises it by its "Cells" key.
const fileVersion = 2

// jailFile is the JSON form of a jail:
//
//	{"version":2,"records":[
//	{"cidr":"10.0.0.0/16","stage":3,"banStart":"2026-11-26T16:45:00Z"}
//	]}
//
// Cells is the content of a file written by package jail.
type jailFile struct {
	Version int          `json:"version"`
	Records []fileRecord `json:"records"`
	Cells   []legacyCell `json:"Cells"`
}

type fileRecord struct {
	CIDR     string    `json:"cidr"`
	Stage    int       `json:"stage"`
	BanStart time.Time `json:"banStart"`
}

// legacyCell is one stage of a file written by package jail. Its position in
// the list is the stage; the ban duration stored with it is not read, the
// stages of the Config apply.
type legacyCell struct {
	Prisoners []struct {
		CIDR     string `json:"Cidr"`
		BanStart time.Time
	}
}

// Encode returns the jail as JSON, one record per line, in address order.
func (j *Jail) Encode() []byte {
	buf := make([]byte, 0, 32+len(j.records)*72)
	buf = append(buf, `{"version":`...)
	buf = strconv.AppendInt(buf, fileVersion, 10)
	buf = append(buf, `,"records":[`...)
	var text [iputils.MaxIPv4Len + 4]byte // one CIDR, as in NumericCIDR.String
	for i := range j.records {
		r := &j.records[i]
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, "\n{\"cidr\":\""...)
		n := iputils.PutIPv4(text[:], r.IP)
		text[n] = '/'
		n = iputils.PutUint8(text[:], n+1, r.PrefixLen)
		buf = append(buf, text[:n]...)
		buf = append(buf, `","stage":`...)
		buf = strconv.AppendInt(buf, int64(r.Stage), 10)
		buf = append(buf, `,"banStart":"`...)
		buf = time.Unix(0, r.BanStart).UTC().AppendFormat(buf, time.RFC3339Nano)
		buf = append(buf, `"}`...)
	}
	return append(buf, "\n]}\n"...)
}

// Decode reads a jail from JSON: the format of Encode, or the format of
// package jail, whose ranges keep their stage and ban start. Empty or blank
// data is an empty jail.
//
// It fails on anything it cannot take over completely - unknown content, an
// entry that is not an IPv4 CIDR, a stage the Config does not have - so that a
// damaged file is never silently replaced by a smaller jail. A range listed
// twice keeps its higher stage, and the result is tidied.
func Decode(data []byte, cfg Config) (*Jail, error) {
	j, err := New(cfg)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return j, nil
	}

	var file jailFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	switch {
	case file.Version == fileVersion && file.Cells == nil:
		for _, fr := range file.Records {
			if err := j.load(fr.CIDR, fr.Stage, fr.BanStart); err != nil {
				return nil, err
			}
		}
	case file.Version == 0 && file.Records == nil && len(file.Cells) > 0:
		for i, cell := range file.Cells {
			// A file with more stages than the Config: the deepest ones
			// share the last stage.
			stage := min(i+1, len(cfg.Stages))
			for _, p := range cell.Prisoners {
				if err := j.load(p.CIDR, stage, p.BanStart); err != nil {
					return nil, err
				}
			}
		}
	default:
		return nil, errors.New("not a jail file: expected \"version\": 2 with \"records\", or the \"Cells\" of the previous format")
	}
	j.normalize()
	return j, nil
}

// load appends one entry of a file to the records, unsorted.
func (j *Jail) load(entry string, stage int, banStart time.Time) error {
	nc, ok := cidr.Parse(entry)
	if !ok {
		return fmt.Errorf("jail entry %q is not an IPv4 CIDR", entry)
	}
	if stage < 1 || stage > len(j.cfg.Stages) {
		return fmt.Errorf("jail entry %q has stage %d, the jail has stages 1 to %d", entry, stage, len(j.cfg.Stages))
	}
	// A time far from the present does not fit into an int64 of nanoseconds.
	// Such an entry keeps its meaning at the limit: ended long ago, or active
	// for good.
	if banStart.Before(minBanStart) {
		banStart = minBanStart
	} else if banStart.After(maxBanStart) {
		banStart = maxBanStart
	}
	j.records = append(j.records, Record{
		IP:        nc.IP,
		PrefixLen: nc.PrefixLen,
		Stage:     uint8(stage),
		BanStart:  banStart.UnixNano(),
	})
	return nil
}

// The ban starts a file may hold. With durations of at most maxDuration, a
// ban end plus the retention computed from them stays inside what an int64 of
// nanoseconds holds (up to the year 2262).
var (
	minBanStart = time.Unix(0, 0).UTC()
	maxBanStart = time.Date(2150, 1, 1, 0, 0, 0, 0, time.UTC)
)

// normalize brings records read from a file into the form the jail keeps:
// sorted, no range twice, tidy.
func (j *Jail) normalize() {
	// Within one range the higher stage first, then the later ban start: the
	// entry that is kept.
	slices.SortFunc(j.records, func(a, b Record) int {
		switch {
		case a.IP != b.IP:
			if a.IP < b.IP {
				return -1
			}
			return 1
		case a.PrefixLen != b.PrefixLen:
			return int(a.PrefixLen) - int(b.PrefixLen)
		case a.Stage != b.Stage:
			return int(b.Stage) - int(a.Stage)
		case a.BanStart != b.BanStart:
			if a.BanStart > b.BanStart {
				return -1
			}
			return 1
		}
		return 0
	})
	recs := j.records
	t := tidier{jail: j, kept: make([]Record, 0, len(recs))}
	for i := range recs {
		if i > 0 && recs[i].IP == recs[i-1].IP && recs[i].PrefixLen == recs[i-1].PrefixLen {
			continue
		}
		t.add(recs[i])
	}
	j.records, j.spare = t.kept, recs[:0]
}

// Load reads the jail file at path. A missing or empty file is an empty jail;
// see Decode for the formats and for what makes it fail.
func Load(path string, cfg Config) (*Jail, error) {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	j, err := Decode(data, cfg)
	if err != nil {
		return nil, fmt.Errorf("jail file %s: %w", path, err)
	}
	return j, nil
}

// Save writes the jail to path through a temporary file and a rename, so a
// reader never sees a partial file.
func (j *Jail) Save(path string) error {
	return jail.WriteToFile(path, string(j.Encode()))
}
