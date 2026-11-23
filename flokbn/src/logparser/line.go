package logparser

import (
	"errors"
	"unsafe"

	"github.com/ChristianF88/flokbn/ingestor"
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
// A LineParser is safe for concurrent use.
type LineParser struct {
	compiled     *CompiledFormat
	hasTimestamp bool
}

// NewLineParser compiles format. It fails exactly when ValidateFormat does.
func NewLineParser(format string) (*LineParser, error) {
	compiled, err := compileFormat(format)
	if err != nil {
		return nil, err
	}
	lp := &LineParser{compiled: compiled}
	for i := range compiled.extractors {
		if compiled.extractors[i].FieldType == 1 {
			lp.hasTimestamp = true
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
func (lp *LineParser) ParseLine(line string, req *ingestor.Request) error {
	*req = ingestor.Request{}
	if len(line) == 0 {
		return ErrInvalidIP
	}
	// The extractors only read the bytes, and the strings they hand out alias
	// them (bytesToString), which is sound because a string is immutable.
	raw := unsafe.Slice(unsafe.StringData(line), len(line))
	if err := lp.compiled.parseLineReuseOpt(raw, req, false, false); err != nil {
		return err
	}
	if req.IPUint32 == 0 {
		return ErrInvalidIP
	}
	if lp.hasTimestamp && req.Timestamp.IsZero() {
		return ErrInvalidTimestamp
	}
	return nil
}

// Stats returns the malformed-field counters, cumulative over every ParseLine
// call including lines that were rejected. OversizedLines is always zero: the
// caller frames the lines.
func (lp *LineParser) Stats() ParseStats {
	return ParseStats{
		MalformedStatus: lp.compiled.counters.malformedStatus.Load(),
		MalformedBytes:  lp.compiled.counters.malformedBytes.Load(),
	}
}
