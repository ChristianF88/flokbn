package logparser

import (
	"bytes"

	"github.com/ChristianF88/flokbn/accesslog"
)

// The two field walkers as they were before the file parser learned to
// re-align a line on the literals of its format (commit 32edf06), copied
// verbatim and only renamed. They are the reference of the differential tests
// in parser_realign_diff_test.go: a line without the anomaly that re-alignment
// repairs must parse exactly as it did with this code.
//
// They take the fields strictly by position and ignore FieldExtractor.resync,
// so they must be run on a positional format (compileFormat), whose delimiters
// enableRealign has not touched.

// legacyParseLine is the previous parseUsingCompiledFormatOpt.
func (cf *CompiledFormat) legacyParseLine(line []byte, req *accesslog.Request, skipStrings, skipNonIP bool) error {
	pos := 0

	for _, extractor := range cf.extractors {
		// Skip whitespace; a line that ends here leaves the remaining fields unset.
		for pos < len(line) && line[pos] == ' ' {
			pos++
		}
		if pos >= len(line) {
			break
		}

		start := pos

		// Scan the field. Each arm leaves pos on the field's exclusive end and
		// sets next to where the following field starts (past the closing quote,
		// bracket or delimiter). The first byte is tested before the per-format
		// flag so a bare token pays two byte compares and nothing else.
		// bytes.IndexByte uses SIMD (SSE2/AVX2) on amd64 for 8-16x faster scanning
		var next int
		quoted := false
		if c := line[pos]; c == '"' && extractor.autoQuote {
			quoted = true
			pos++ // skip opening quote
			start = pos
			if pos+1 < len(line) && line[pos] == '-' && line[pos+1] == '"' {
				pos++ // "-" (absent value): cheaper than the IndexByte call
			} else if idx := bytes.IndexByte(line[pos:], '"'); idx >= 0 {
				if idx > 0 && line[pos+idx-1] == '\\' {
					pos = scanQuotedClose(line, pos, pos+idx) // rare slow path: escaped quote
				} else {
					pos += idx
				}
			} else {
				pos = len(line)
			}
			next = pos
			if pos < len(line) {
				next++ // closing quote
				if next < len(line) && line[next] == extractor.after {
					next++ // and the delimiter behind it
				}
			}
		} else if c == '[' && extractor.Brackets {
			pos++ // skip opening bracket
			start = pos
			if idx := bytes.IndexByte(line[pos:], ']'); idx >= 0 {
				pos += idx
			} else {
				pos = len(line)
			}
			next = pos
			if pos < len(line) {
				next++ // closing bracket
				if next < len(line) && line[next] == extractor.after {
					next++ // and the delimiter behind it
				}
			}
		} else {
			// Regular field - scan until delimiter or space
			delimiter := extractor.Delimiter
			for pos < len(line) && line[pos] != delimiter && line[pos] != ' ' {
				pos++
			}
			next = pos
			if pos < len(line) && line[pos] == delimiter {
				next++ // the delimiter itself
			}
		}

		// Extract and parse field if not skipped
		if extractor.FieldType >= 0 && start < pos {
			// IP is always extracted; other fields are skipped when skipNonIP is true
			if extractor.FieldType == 0 {
				ip := parseIPv4ToUint32(line, start, pos)
				if ip == 0 {
					ip = forwardedTailIP(line, start, pos) // slow path: address list
				}
				req.IPUint32 = ip
			} else if !skipNonIP {
				fieldData := line[start:pos]

				switch extractor.FieldType {
				case 1: // Timestamp
					req.Timestamp = parseTimestamp(line, start, pos)
				case 2: // Method (standalone)
					req.Method = parseMethod(line, start, pos)
				case 3: // Request line (%r) - extracts METHOD and URI, ignores HTTP version
					if extractor.Quoted || quoted {
						// Parse "METHOD URI HTTP/VERSION" format efficiently
						methodEnd := start
						for methodEnd < pos && line[methodEnd] != ' ' {
							methodEnd++
						}

						// Fill Method from the request line ONLY when the format has no
						// standalone %m. When a %m extractor exists it is authoritative,
						// so %r must not overwrite it. Using the zero value (GET==0) as
						// an "unset" sentinel would silently clobber a %m-parsed GET.
						if methodEnd > start && !cf.hasMethodField {
							req.Method = parseMethod(line, start, methodEnd)
						}

						// Extract URI only if strings are needed
						if !skipStrings {
							// Skip spaces after method
							uriStart := methodEnd
							for uriStart < pos && line[uriStart] == ' ' {
								uriStart++
							}

							// Find end of URI (next space before HTTP version)
							uriEnd := uriStart
							for uriEnd < pos && line[uriEnd] != ' ' {
								uriEnd++
							}

							// Extract URI
							if uriEnd > uriStart {
								req.URI = bytesToString(line[uriStart:uriEnd])
							}
						}
						// HTTP version is intentionally ignored as Request struct has no field for it
					} else if !skipStrings {
						// If not quoted, treat entire field as URI
						req.URI = bytesToString(fieldData)
					}
				case 4: // Status
					if pos-start == 3 {
						_ = line[start+2] // BCE hint: eliminate 3 individual bounds checks below
						d0 := line[start] - '0'
						d1 := line[start+1] - '0'
						d2 := line[start+2] - '0'
						// Do NOT or-fold these checks: (d0|d1|d2)<=9 is wrong (2|9==11).
						// Each d<=9 byte compare exploits unsigned wraparound for non-digits.
						if d0 <= 9 && d1 <= 9 && d2 <= 9 {
							req.Status = uint16(d0)*100 + uint16(d1)*10 + uint16(d2)
						} else {
							cf.counters.malformedStatus.Add(1)
						}
					} else if !(pos-start == 1 && line[start] == '-') {
						// "-" = absent (Apache convention): silent zero. Anything else: malformed.
						cf.counters.malformedStatus.Add(1)
					}
				case 5: // Bytes
					if len(fieldData) > 0 && fieldData[0] != '-' {
						b, ok := parseBytes(line, start, pos)
						req.Bytes = b
						if !ok {
							cf.counters.malformedBytes.Add(1)
						}
					}
				case 6: // User agent
					if !skipStrings {
						req.UserAgent = bytesToString(fieldData)
					}
				case 7: // URI (standalone)
					if !skipStrings {
						req.URI = bytesToString(fieldData)
					}
				}
			}
		}

		// Advance past closing quotes/brackets/delimiters
		pos = next
	}

	return nil
}

// legacyExtractIPOnly is the previous extractIPOnly.
func (cf *CompiledFormat) legacyExtractIPOnly(line []byte) uint32 {
	pos := 0

	for ei := range cf.extractors {
		extractor := &cf.extractors[ei]

		// Skip whitespace; a line that ends here has no IP field.
		for pos < len(line) && line[pos] == ' ' {
			pos++
		}
		if pos >= len(line) {
			break
		}

		start := pos

		// Scan the field - identical boundary logic to
		// parseUsingCompiledFormatOpt so that pos and next land on the same
		// offsets.
		var next int
		if c := line[pos]; c == '"' && extractor.autoQuote {
			pos++ // skip opening quote
			start = pos
			if pos+1 < len(line) && line[pos] == '-' && line[pos+1] == '"' {
				pos++ // "-" (absent value): cheaper than the IndexByte call
			} else if idx := bytes.IndexByte(line[pos:], '"'); idx >= 0 {
				if idx > 0 && line[pos+idx-1] == '\\' {
					pos = scanQuotedClose(line, pos, pos+idx) // rare slow path: escaped quote
				} else {
					pos += idx
				}
			} else {
				pos = len(line)
			}
			next = pos
			if pos < len(line) {
				next++ // closing quote
				if next < len(line) && line[next] == extractor.after {
					next++ // and the delimiter behind it
				}
			}
		} else if c == '[' && extractor.Brackets {
			pos++ // skip opening bracket
			start = pos
			if idx := bytes.IndexByte(line[pos:], ']'); idx >= 0 {
				pos += idx
			} else {
				pos = len(line)
			}
			next = pos
			if pos < len(line) {
				next++ // closing bracket
				if next < len(line) && line[next] == extractor.after {
					next++ // and the delimiter behind it
				}
			}
		} else {
			delimiter := extractor.Delimiter
			for pos < len(line) && line[pos] != delimiter && line[pos] != ' ' {
				pos++
			}
			next = pos
			if pos < len(line) && line[pos] == delimiter {
				next++ // the delimiter itself
			}
		}

		// IP field: parse and return immediately. The guard `start < pos`
		// matches the original (only fields with content are parsed); when the
		// IP field has no content we fall through and return 0 below, which is
		// exactly what req.IPUint32 would remain (zero value).
		if extractor.FieldType == 0 {
			if start < pos {
				if ip := parseIPv4ToUint32(line, start, pos); ip != 0 {
					return ip
				}
				return forwardedTailIP(line, start, pos) // slow path: address list
			}
			return 0
		}

		// Advance past closing quotes/brackets/delimiters - identical to
		// parseUsingCompiledFormatOpt so subsequent field boundaries align.
		pos = next
	}

	return 0
}
