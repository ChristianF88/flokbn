package logparser

import (
	"bytes"
	"errors"
	"strings"
	"unsafe"

	"github.com/ChristianF88/flokbn/accesslog"
)

// DefaultLiveLogFormat is the format live mode uses when no logFormat is
// configured: the combined log format with the client IP in the FIRST field,
// which is what a web server writes by default and what Filebeat ships
// unchanged.
//
// It deliberately differs from DefaultLogFormat (static mode), which reads the
// client IP from a trailing quoted field. Live mode always read the first
// field, so this default keeps existing shippers working; set logFormat on
// both sides to the same string when both modes read the same log.
const DefaultLiveLogFormat = `%h %^ %^ [%t] "%r" %s %b "%^" "%u"`

// Errors returned by LineParser.ParseLine. They are fixed values so rejecting
// a line allocates nothing.
var (
	// ErrInvalidIP: the %h field is missing or is not an IPv4 address. Every
	// IPv6 form and 0.0.0.0 end up here too.
	ErrInvalidIP = errors.New("invalid IP")
	// ErrInvalidTimestamp: the format has a %t field and the line's value is
	// missing or not a valid timestamp.
	ErrInvalidTimestamp = errors.New("invalid timestamp")
)

// LineParser parses one log line at a time with a compiled format. It is the
// entry point for callers that already hold single lines (live mode gets them
// from the shipper); Parser is the one for files. Both run the same compiled
// extractors, so a format means the same thing in either mode.
//
// One thing is added on top: a line whose bracketed timestamp is not where the
// format puts it is re-aligned on that timestamp (see realign) instead of
// being rejected.
//
// A LineParser is safe for concurrent use.
type LineParser struct {
	compiled     *CompiledFormat
	hasTimestamp bool
	// head and tail are the extractors before the timestamp field and from it
	// on. They are set only when the format brackets its timestamp ("[%t]"),
	// which is what makes the timestamp findable in a misaligned line.
	head, tail *CompiledFormat
}

// NewLineParser compiles format. It fails exactly when ValidateFormat does.
func NewLineParser(format string) (*LineParser, error) {
	compiled, err := compileFormat(format)
	if err != nil {
		return nil, err
	}
	lp := &LineParser{compiled: compiled}
	for i := range compiled.extractors {
		if compiled.extractors[i].FieldType != 1 {
			continue
		}
		lp.hasTimestamp = true
		if strings.Contains(format, "[%t]") {
			head, tail := *compiled, *compiled // share the counters
			head.extractors = compiled.extractors[:i]
			tail.extractors = compiled.extractors[i:]
			lp.head, lp.tail = &head, &tail
		}
	}
	return lp, nil
}

// Format returns the format string the parser was compiled from.
func (lp *LineParser) Format() string {
	return lp.compiled.pattern
}

// ParseLine parses line into req, overwriting whatever req held. It returns
// ErrInvalidIP or ErrInvalidTimestamp for a line that cannot be used; every
// other oddity (a truncated line, a non-numeric status) leaves the affected
// fields at their zero value, exactly as in a file parse.
//
// URI and UserAgent are substrings of line: they share its memory and keep it
// reachable for as long as the Request lives. ParseLine does not allocate.
func (lp *LineParser) ParseLine(line string, req *accesslog.Request) error {
	*req = accesslog.Request{}
	if len(line) == 0 {
		return ErrInvalidIP
	}
	// The extractors only read the bytes, and the strings they hand out alias
	// them (bytesToString), which is sound because a string is immutable.
	raw := unsafe.Slice(unsafe.StringData(line), len(line))
	if err := lp.compiled.parseLineReuseOpt(raw, req, false, false); err != nil {
		return err
	}
	if lp.hasTimestamp && req.Timestamp.IsZero() {
		if lp.tail != nil {
			lp.realign(raw, req) // slow path
		}
		if req.IPUint32 != 0 && req.Timestamp.IsZero() {
			return ErrInvalidTimestamp
		}
	}
	if req.IPUint32 == 0 {
		return ErrInvalidIP
	}
	return nil
}

// maxTimestampLen bounds how far realign looks for the "]" that closes a
// timestamp candidate. A timestamp with a zone offset is 26 bytes.
const maxTimestampLen = 64

// realign is the slow path for a line whose timestamp did not parse at the
// position the format gives it. The usual cause is a free-text field in front
// of it that holds a space - the user name of the common log format is
// whatever the client sent as its basic-auth name - or a log that has more or
// fewer such fields than the format says. Every field behind it then sits one
// slot off and the line would be dropped: a client could hide from live mode
// with a space in its user name.
//
// The timestamp is the one field that can be recognised by its content, so the
// line is re-anchored on it: the first "[...]" that holds a valid timestamp is
// taken as the %t field, the extractors in front of %t parse what precedes it
// and the extractors from %t on parse the rest. If no bracket holds a valid
// timestamp, req is left as the first pass filled it.
//
// The work is linear in the line length: each "[" costs one bounded search for
// its "]" and one timestamp check that fails within the first few bytes.
func (lp *LineParser) realign(raw []byte, req *accesslog.Request) {
	for open := 0; ; open++ {
		i := bytes.IndexByte(raw[open:], '[')
		if i < 0 {
			return
		}
		open += i
		window := raw[open+1:]
		if len(window) > maxTimestampLen {
			window = window[:maxTimestampLen]
		}
		n := bytes.IndexByte(window, ']')
		if n < 0 || parseTimestamp(raw, open+1, open+1+n).IsZero() {
			continue
		}
		lp.uncount(raw)
		*req = accesslog.Request{}
		_ = lp.head.parseLineReuseOpt(raw[:open], req, false, false)
		_ = lp.tail.parseLineReuseOpt(raw[open:], req, false, false)
		return
	}
}

// uncount takes back what the first pass over a misaligned line added to the
// malformed-field counters: it read status and bytes from the wrong slots, and
// the re-aligned parse counts them again from the right ones. The first pass
// is repeated against private counters to learn its exact contribution, which
// keeps this correct when several goroutines share the parser.
func (lp *LineParser) uncount(raw []byte) {
	var seen parseCounters
	first := *lp.compiled
	first.counters = &seen
	var discard accesslog.Request
	_ = first.parseLineReuseOpt(raw, &discard, true, false)
	if n := seen.malformedStatus.Load(); n != 0 {
		lp.compiled.counters.malformedStatus.Add(-n)
	}
	if n := seen.malformedBytes.Load(); n != 0 {
		lp.compiled.counters.malformedBytes.Add(-n)
	}
}

// Stats returns the malformed-field counters, cumulative over every ParseLine
// call. The fields are counted as they are scanned, so a line that ends up
// rejected is included, as it is in a file parse. OversizedLines is always
// zero: the caller frames the lines.
func (lp *LineParser) Stats() ParseStats {
	return ParseStats{
		MalformedStatus: lp.compiled.counters.malformedStatus.Load(),
		MalformedBytes:  lp.compiled.counters.malformedBytes.Load(),
	}
}
