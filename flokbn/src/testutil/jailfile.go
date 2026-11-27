package testutil

import (
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
