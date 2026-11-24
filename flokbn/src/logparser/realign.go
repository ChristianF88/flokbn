package logparser

import (
	"bytes"
	"time"
)

// Re-alignment: the literals of a format delimit its fields.
//
// The walkers take a bare field (no quotes, no brackets) up to the first
// space. Some bare fields are free text that the client chooses - the user
// name of the combined log format is the basic-auth name it sent - so a space
// inside one used to move every later field one slot on: the line was dropped
// as an invalid IP, or %h was read from a slot the client also controls.
//
// A format that is properly specified says where such a field ends, because
// it puts a literal behind it that the value cannot be confused with:
//
//   - a bracketed timestamp, " [%t]": the timestamp is recognised by its
//     content, so everything from %t on is read from the real timestamp;
//   - a quoted slot, ` "%r"`: the slot starts at the next quote that follows a
//     space;
//   - a delimiter other than a space, "%U|": the value runs to the delimiter.
//
// Only a bare field that is followed by a single space and another bare field
// ("%^ %^", "%U %s") has no such literal. There the first space still ends
// the field: which of two neighbouring bare fields a space belongs to cannot
// be known.
//
// None of this costs a line that follows its format anything. The walkers'
// bare scan ends with the test "did the value stop on its delimiter?", and
// that test is where a misaligned line shows: what sits in the slot is a bare
// token that stopped at a space although the format ends the slot with
// something else. Only then is realignBare called. Everything here is linear
// in the line length and allocates nothing - the lines are written by
// clients.
//
// The file parser (NewParser) enables this. compileFormat on its own yields a
// strictly positional format, which is what LineParser builds on: live mode
// has its own, older re-alignment (LineParser.realign) and shares the
// timestamp search with this one.

// slotAnchor is what the format literally puts around one slot.
type slotAnchor struct {
	selfQuoted  bool // "%x": a quote directly before and after the specifier
	bracketed   bool // [%x]
	spaceBefore bool // a space in front of the opening quote or bracket
	specifierOn bool // the next specifier follows directly (%^%h): no delimiter
}

// What a walker does with a bare value that stopped at a space although its
// slot's delimiter is not a space.
const (
	// resyncNone: nothing - the value ends at the space (positional reading).
	resyncNone uint8 = iota
	// resyncSpan: the slot is a bare free-text field with a delimiter of its
	// own ("%U|"). The value runs on to that delimiter.
	resyncSpan
	// resyncTimestamp: the slot is "[%t]". Unless the bare token is itself a
	// valid timestamp, the slot is the next bracket that holds one.
	resyncTimestamp
	// resyncQuote: the slot is ` "%x"` behind a bare free-text field. The slot
	// is the next quote that follows a space.
	resyncQuote
	// resyncQuoteAfterTimestamp: the same behind "[%t]". The bracketed field
	// that directly precedes the quote is then the line's timestamp.
	resyncQuoteAfterTimestamp
)

// noDelimiter is the Delimiter of a slot that can be re-aligned on its opener
// (every resync kind but resyncSpan). No line holds this byte - the readers
// split on it - so a bare token in such a slot ends at a space or at the end
// of the line and nowhere else, and the walker's delimiter test sends every
// such token that is followed by more of the line to realignBare. With the
// slot's real closer as the delimiter, a token that happens to end in that
// closer ("doe]" in front of the timestamp) would pass for a value.
const noDelimiter = '\n'

// isFreeText reports whether a field of this type can hold a space: a skipped
// field, a URI, a request line, a User-Agent, a timestamp with a zone offset.
// An address, a method, a status and a byte count cannot.
func isFreeText(fieldType int) bool {
	switch fieldType {
	case -1, 1, 3, 6, 7:
		return true
	}
	return false
}

// enableRealign turns the positional format into one whose walks re-align a
// line on the format's literals. It works on a copy of the extractors, so a
// format that was copied before stays positional.
func (cf *CompiledFormat) enableRealign() {
	exts := make([]FieldExtractor, len(cf.extractors))
	copy(exts, cf.extractors)

	for i := range exts {
		e, a := &exts[i], cf.anchors[i]
		switch {
		case a.bracketed && e.FieldType == 1:
			e.resync = resyncTimestamp
		case a.selfQuoted && a.spaceBefore && i > 0:
			prev, pa := cf.extractors[i-1], cf.anchors[i-1]
			if pa.bracketed && prev.FieldType == 1 {
				e.resync = resyncQuoteAfterTimestamp
			} else if !pa.selfQuoted && isFreeText(prev.FieldType) && prev.Delimiter == ' ' {
				e.resync = resyncQuote
			}
		case isFreeText(e.FieldType) && !a.selfQuoted && !a.specifierOn && e.Delimiter != ' ':
			e.resync = resyncSpan
		}
		if e.resync > resyncSpan {
			e.Delimiter = noDelimiter
		}
	}
	cf.extractors = exts
}

// realignBare is the walkers' slow path. The slot's value started at start as
// a bare token and stopped at the space at pos, but the format does not end
// this slot with a space. It returns the bounds of the slot's value and the
// start of the next field, like the walkers' own scan arms.
//
// delimiter is the slot's delimiter (used by resyncSpan only), after the
// literal behind the slot's closing quote or bracket. ts, when not nil, is the
// request's timestamp - see trailingTimestamp.
func realignBare(line []byte, start, pos int, delimiter, after byte, kind uint8, ts *time.Time) (valueStart, end, next int) {
	switch kind {
	case resyncSpan:
		end, next = spanToDelimiter(line, start, pos, delimiter)
		return start, end, next

	case resyncTimestamp:
		// A valid timestamp without brackets is the slot's value, as it always
		// was. Anything else in front of the timestamp is the overflow of an
		// earlier field: skip to the first bracket that holds a timestamp.
		end, next = bareUpTo(line, start, pos, ']')
		if !parseTimestamp(line, start, end).IsZero() {
			return start, end, next
		}
		if at := findBracketedTimestamp(line, start); at >= 0 {
			return scanEnclosed(line, at, after, false)
		}
		return start, end, next

	default: // resyncQuote, resyncQuoteAfterTimestamp
		// The server writes a quote in front of this slot's value, and a client
		// cannot write one into a bare field in front of it (web servers escape
		// it there). So the first quote that follows a space opens the slot.
		for i := pos; ; i++ {
			j := bytes.IndexByte(line[i:], '"')
			if j < 0 {
				break
			}
			i += j
			if line[i-1] != ' ' {
				continue
			}
			if kind == resyncQuoteAfterTimestamp && ts != nil {
				if t := trailingTimestamp(line, start, i); !t.IsZero() {
					*ts = t
				}
			}
			return scanEnclosed(line, i, after, true)
		}
		end, next = bareUpTo(line, start, pos, '"')
		return start, end, next
	}
}

// bareUpTo gives the positional reading of the bare token line[start:pos] in
// a slot the format closes with closer: the value ends at the first closer
// inside the token (which is consumed) or else at pos.
func bareUpTo(line []byte, start, pos int, closer byte) (end, next int) {
	if i := bytes.IndexByte(line[start:pos], closer); i >= 0 {
		return start + i, start + i + 1
	}
	return pos, pos
}

// scanEnclosed scans the quoted (or bracketed) value whose opener is at
// line[at], exactly as the walkers' inline arms do: up to the first unescaped
// quote (or the first "]"), or to the end of the line when it is not closed.
func scanEnclosed(line []byte, at int, after byte, quoted bool) (start, end, next int) {
	start = at + 1
	end = len(line)
	if quoted {
		if idx := bytes.IndexByte(line[start:], '"'); idx >= 0 {
			end = start + idx
			if idx > 0 && line[end-1] == '\\' {
				end = scanQuotedClose(line, start, end)
			}
		}
	} else if idx := bytes.IndexByte(line[start:], ']'); idx >= 0 {
		end = start + idx
	}
	next = end
	if end < len(line) {
		next++ // the closer
		if next < len(line) && line[next] == after {
			next++ // and the delimiter behind it
		}
	}
	return start, end, next
}

// trailingTimestamp returns the timestamp of a bracketed field that ends
// line[from:to] (trailing spaces aside), or the zero time. realignBare calls
// it with the bytes it skips between a timestamp slot and the quoted slot
// behind it: the server writes its timestamp directly in front of that quote,
// so this one is genuine, and whatever the timestamp slot picked up before it
// is not - a client can put brackets, even a valid timestamp, into a bare
// field.
func trailingTimestamp(line []byte, from, to int) time.Time {
	end := to
	for end > from && line[end-1] == ' ' {
		end--
	}
	if end <= from || line[end-1] != ']' {
		return time.Time{}
	}
	lo := end - 1 - maxTimestampLen
	if lo < from {
		lo = from
	}
	open := bytes.LastIndexByte(line[lo:end-1], '[')
	if open < 0 {
		return time.Time{}
	}
	return parseTimestamp(line, lo+open+1, end-1)
}

// spanToDelimiter is called when a bare free-text value that started at start
// stopped at the space at pos although its slot is delimited by something
// else. It returns the value's end and the start of the next field: the
// delimiter and the byte behind it, or (pos, pos) - the positional reading -
// when the rest of the line has no such delimiter. A closing quote (the last
// field of a quoted group) is found the way a quoted field finds its own, so
// an escaped quote does not end the value.
func spanToDelimiter(line []byte, start, pos int, delimiter byte) (end, next int) {
	idx := bytes.IndexByte(line[pos:], delimiter)
	if idx < 0 {
		return pos, pos
	}
	end = pos + idx
	if delimiter == '"' && line[end-1] == '\\' {
		if end = scanQuotedClose(line, start, end); end >= len(line) {
			return pos, pos
		}
	}
	return end, end + 1
}

// realignIP is realignBare for the IP-only walker, which holds the extractor
// by pointer and has no timestamp to correct. Passing the pointer keeps the
// call - and with it the walker's register use on its fast path - small.
func (e *FieldExtractor) realignIP(line []byte, start, pos int) (valueStart, end, next int) {
	return realignBare(line, start, pos, e.Delimiter, e.after, e.resync, nil)
}
