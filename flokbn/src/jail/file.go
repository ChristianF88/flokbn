package jail

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/ChristianF88/flokbn/cidr"
)

// fileVersion marks the file format.
const fileVersion = 2

// The JSON form of a jail:
//
//	{"version":2,"records":[
//	{"cidr":"10.0.0.0/16","stage":3,"banStart":"2026-11-26T16:45:00Z"}
//	]}
//
// The fields are pointers so that Decode can tell a missing one from a zero.
type fileRecord struct {
	CIDR     *string    `json:"cidr"`
	Stage    *int       `json:"stage"`
	BanStart *time.Time `json:"banStart"`
}

// Encode returns the jail as JSON, one record per line, in address order.
func (j *Jail) Encode() []byte {
	buf := make([]byte, 0, 32+len(j.records)*72)
	buf = append(buf, `{"version":`...)
	buf = strconv.AppendInt(buf, fileVersion, 10)
	buf = append(buf, `,"records":[`...)
	for i := range j.records {
		r := &j.records[i]
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, "\n{\"cidr\":\""...)
		buf = appendCIDR(buf, r.CIDR())
		buf = append(buf, `","stage":`...)
		buf = strconv.AppendInt(buf, int64(r.Stage), 10)
		buf = append(buf, `,"banStart":"`...)
		buf = time.Unix(0, r.BanStart).UTC().AppendFormat(buf, time.RFC3339Nano)
		buf = append(buf, `"}`...)
	}
	return append(buf, "\n]}\n"...)
}

// Decode reads a jail from JSON in the format of Encode. Empty or blank data
// is an empty jail.
//
// It fails on anything it cannot take over completely, so that a damaged file
// is never silently replaced by a smaller jail: an unknown or repeated key, a
// record without its range, stage or ban start, an entry that is not an IPv4
// CIDR, a range listed twice. A stage above those of the Config becomes its
// last stage.
//
// The jail's time starts at the latest ban start in the file (see Time in the
// package comment).
func Decode(data []byte, cfg Config) (*Jail, error) {
	j, err := New(cfg)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return j, nil
	}

	records, err := readFile(data)
	if err != nil {
		return nil, err
	}
	for i, fr := range records {
		if fr.CIDR == nil || fr.Stage == nil || fr.BanStart == nil {
			return nil, fmt.Errorf("jail record %d lacks its cidr, stage or banStart", i+1)
		}
		if err := j.load(*fr.CIDR, *fr.Stage, *fr.BanStart); err != nil {
			return nil, err
		}
	}
	if err := j.normalize(); err != nil {
		return nil, err
	}
	for i := range j.records {
		j.clock = max(j.clock, j.records[i].BanStart)
	}
	return j, nil
}

var (
	errNotJailFile = errors.New("not a jail file: expected \"version\": 2 with \"records\"")
	errOldJailFile = errors.New("jail file of an earlier flokbn version (\"Cells\"), which this version does not read: delete it to start with an empty jail")
)

// readFile takes a jail file apart and returns its records. It reads the
// top-level keys one by one, because encoding/json alone would accept a key
// in any spelling of upper and lower case and let a repeated key replace the
// first.
func readFile(data []byte) ([]fileRecord, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil {
		return nil, err
	} else if tok != json.Delim('{') {
		return nil, errNotJailFile
	}
	keys := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		if _, twice := keys[key]; twice {
			return nil, fmt.Errorf("jail file has the key %q twice", key)
		}
		keys[key] = value
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("jail file continues after its closing brace")
	}

	version, hasVersion := keys["version"]
	list, hasRecords := keys["records"]
	if !hasVersion || !hasRecords {
		if _, old := keys["Cells"]; old && !hasVersion && !hasRecords {
			return nil, errOldJailFile
		}
		return nil, errNotJailFile
	}
	for key := range keys {
		if key != "version" && key != "records" {
			return nil, fmt.Errorf("jail file has the unknown key %q", key)
		}
	}
	var v int
	if err := json.Unmarshal(version, &v); err != nil || v != fileVersion {
		return nil, fmt.Errorf("jail file has the version %s, this flokbn reads version %d", version, fileVersion)
	}
	if list[0] != '[' {
		return nil, errors.New("jail file: \"records\" is not a list")
	}
	var records []fileRecord
	strict := json.NewDecoder(bytes.NewReader(list))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&records); err != nil {
		return nil, err
	}
	return records, nil
}

// load appends one entry of a file to the records, unsorted.
func (j *Jail) load(entry string, stage int, banStart time.Time) error {
	nc, ok := cidr.Parse(entry)
	if !ok {
		return fmt.Errorf("jail entry %q is not an IPv4 CIDR", entry)
	}
	if stage < 1 {
		return fmt.Errorf("jail entry %q has stage %d, stages start at 1", entry, stage)
	}
	// A file with more stages than the Config: the deepest ones share the
	// last stage.
	stage = min(stage, len(j.cfg.Stages))
	// A time far from the present does not fit into an int64 of nanoseconds.
	// Such an entry keeps its meaning at the limit: ended long ago, or active
	// for good.
	j.records = append(j.records, Record{
		IP:        nc.IP,
		PrefixLen: nc.PrefixLen,
		Stage:     uint8(stage),
		BanStart:  clampNano(banStart),
	})
	return nil
}

// normalize brings records read from a file into the order the jail keeps
// and fails on a range that is listed twice.
func (j *Jail) normalize() error {
	slices.SortFunc(j.records, func(a, b Record) int {
		if a.IP != b.IP {
			if a.IP < b.IP {
				return -1
			}
			return 1
		}
		return int(a.PrefixLen) - int(b.PrefixLen)
	})
	for i := 1; i < len(j.records); i++ {
		if j.records[i].CIDR() == j.records[i-1].CIDR() {
			return fmt.Errorf("jail file lists %s twice", j.records[i].CIDR())
		}
	}
	return nil
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
	return writeFileAtomic(path, j.Encode(), 0o644)
}
