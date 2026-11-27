package testutil

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// JailRecord is one record of a jail file: a range, the stage of its last ban
// and the time that ban started.
type JailRecord struct {
	CIDR     string
	Stage    int
	BanStart time.Time
}

// JailJSON returns a jail file holding the records, in the format of package
// jail. Tests use it to start from a jail with a history.
func JailJSON(records ...JailRecord) string {
	var b strings.Builder
	b.WriteString(`{"version":2,"records":[`)
	for i, r := range records {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "\n{\"cidr\":%q,\"stage\":%d,\"banStart\":%q}", r.CIDR, r.Stage, r.BanStart.UTC().Format(time.RFC3339Nano))
	}
	b.WriteString("\n]}\n")
	return b.String()
}

// WriteJailFile writes a jail file holding the records to path.
func WriteJailFile(t testing.TB, path string, records ...JailRecord) {
	t.Helper()
	if err := os.WriteFile(path, []byte(JailJSON(records...)), 0o644); err != nil {
		t.Fatalf("writing jail file: %v", err)
	}
}

// JailRecords returns the records of a jail file, in file order (address
// order for a file from jail.Encode). It is the inverse of JailJSON: tests read
// a jail through the file it saves, ended records included.
func JailRecords(t testing.TB, data []byte) []JailRecord {
	t.Helper()
	var file struct {
		Records []struct {
			CIDR     string    `json:"cidr"`
			Stage    int       `json:"stage"`
			BanStart time.Time `json:"banStart"`
		} `json:"records"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("reading jail file: %v", err)
	}
	records := make([]JailRecord, len(file.Records))
	for i, r := range file.Records {
		records[i] = JailRecord{CIDR: r.CIDR, Stage: r.Stage, BanStart: r.BanStart}
	}
	return records
}
