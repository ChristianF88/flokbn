package logparser

import (
	"fmt"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
)

// TestParseIPv4_RequiresWellFormedOctets: every octet needs one to three
// digits. An empty octet used to read as 0 ("1.2..34" -> 1.2.0.34 and
// "1.2.34." -> 1.2.34.0), turning malformed text into a real address.
func TestParseIPv4_RequiresWellFormedOctets(t *testing.T) {
	tests := []struct {
		in   string
		want string // "" = rejected
	}{
		{"1.2.3.4", "1.2.3.4"},
		{"255.255.255.255", "255.255.255.255"},
		{"10.0.0.1", "10.0.0.1"},
		{"001.002.003.004", "1.2.3.4"}, // leading zeros within three digits stay accepted
		{"0.0.0.1", "0.0.0.1"},

		{"1.2..34", ""},  // empty third octet
		{"1.2.34.", ""},  // empty last octet
		{".1.2.34", ""},  // empty first octet
		{"1..2.34", ""},  // empty second octet
		{"12.34...", ""}, // two empty octets
		{"1234...", ""},
		{".......", ""},
		{"0001.2.3.4", ""}, // four digits
		{"1.2.3.0004", ""},
		{"1.0256.3.4", ""},
		{"0000000.1.1.1", ""},
		{"256.1.1.1", ""},
		{"1.2.3.256", ""},
		{"1.2.3", ""},
		{"1.2.3.4.5", ""},
	}
	for _, tt := range tests {
		b := []byte(tt.in)
		got := parseIPv4ToUint32(b, 0, len(b))
		var want uint32
		if tt.want != "" {
			want = ipStringToUint32(tt.want)
		}
		if got != want {
			t.Errorf("parseIPv4ToUint32(%q) = %s, want %s", tt.in, accesslog.Uint32ToIPString(got), accesslog.Uint32ToIPString(want))
		}
	}
}

// TestParseIPv4_MalformedCountsAsInvalid: through the file API a malformed
// address is an invalid line, not a request from a made-up address.
func TestParseIPv4_MalformedCountsAsInvalid(t *testing.T) {
	path := writeFixture(t, "1.2..34 a\n1.2.34. b\n1.2.3.4 c\n")
	p := mustNewParser(t, `%h %^`)
	ips, invalid, err := p.ParseFileIPs(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != ipStringToUint32("1.2.3.4") || invalid != 2 {
		t.Errorf("got ips=%v invalid=%d, want [1.2.3.4] and 2 invalid", ips, invalid)
	}
}

// TestParseTimestamp_ValidatesDigits: each of the 12 digit positions must hold
// an ASCII digit. They used to be masked with 0x0F, so "1a" read as 11 and
// arbitrary text became a plausible-looking time.
func TestParseTimestamp_ValidatesDigits(t *testing.T) {
	const good = "06/Jul/2025:19:57:26 +0200"
	want := time.Date(2025, time.July, 6, 19, 57, 26, 0, time.FixedZone("", 2*3600))
	if got := parseTimestamp([]byte(good), 0, len(good)); !got.Equal(want) {
		t.Fatalf("parseTimestamp(%q) = %v, want %v", good, got, want)
	}

	digitPositions := []int{0, 1, 7, 8, 9, 10, 12, 13, 15, 16, 18, 19}
	// Bytes around the digit range and bytes whose low nibble looks like a digit.
	bad := []byte{'a', 'A', 'q', ' ', '/', ':', ';', '-', '.', 0x00, 0x10, 0x41, 0x80, 0xB5, 0xFF}
	for _, pos := range digitPositions {
		for _, c := range bad {
			b := []byte(good)
			b[pos] = c
			if got := parseTimestamp(b, 0, len(b)); !got.IsZero() {
				t.Errorf("non-digit %q at position %d: parseTimestamp(%q) = %v, want zero time", c, pos, b, got)
			}
		}
	}
}

// TestNotDigitBits pins the branch-free digit test for every byte value.
func TestNotDigitBits(t *testing.T) {
	for c := 0; c < 256; c++ {
		isDigit := c >= '0' && c <= '9'
		flagged := notDigitBits(byte(c)-'0')&0xF0 != 0
		if flagged == isDigit {
			t.Errorf("byte %#02x: flagged as non-digit = %v, is digit = %v", c, flagged, isDigit)
		}
	}
}

// TestParseTimestamp_ValidatesRanges: out-of-range values are rejected instead
// of being normalised into a different instant (hour 25 -> next day 01:00).
func TestParseTimestamp_ValidatesRanges(t *testing.T) {
	valid := []string{
		"01/Jan/2025:00:00:00",
		"31/Dec/2025:23:59:59",
		"29/Feb/2024:12:00:00", // leap year
		"29/Feb/2000:12:00:00", // divisible by 400
		"30/Apr/2025:12:00:00",
		"31/Jul/2025:12:00:00",
	}
	for _, s := range valid {
		if got := parseTimestamp([]byte(s), 0, len(s)); got.IsZero() {
			t.Errorf("parseTimestamp(%q) = zero time, want a valid time", s)
		} else if want := got.Format("02/Jan/2006:15:04:05"); want != s {
			t.Errorf("parseTimestamp(%q) round-trips to %q", s, want)
		}
	}

	invalid := []string{
		"00/Jul/2025:19:57:26", // day 0
		"32/Jul/2025:19:57:26",
		"31/Apr/2025:19:57:26", // April has 30 days
		"30/Feb/2024:19:57:26",
		"29/Feb/2025:19:57:26", // not a leap year
		"29/Feb/1900:19:57:26", // divisible by 100, not by 400
		"99/Jul/2025:19:57:26",
		"06/Jul/2025:24:00:00",
		"06/Jul/2025:99:57:26",
		"06/Jul/2025:19:60:26",
		"06/Jul/2025:19:57:60",
		"06/Jul/2025:19:57:99",
	}
	for _, s := range invalid {
		if got := parseTimestamp([]byte(s), 0, len(s)); !got.IsZero() {
			t.Errorf("parseTimestamp(%q) = %v, want zero time", s, got)
		}
	}
}

// TestParseTimestamp_MatchesTimeParse: for well-formed and near-miss inputs the
// fast parser accepts exactly what the standard library layout accepts, and
// agrees on the instant.
func TestParseTimestamp_MatchesTimeParse(t *testing.T) {
	const layout = "02/Jan/2006:15:04:05"
	months := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	for _, year := range []int{1999, 2000, 2023, 2024, 2025, 2100} {
		for _, mon := range months {
			for _, day := range []int{0, 1, 28, 29, 30, 31, 32} {
				for _, hms := range [][3]int{{0, 0, 0}, {23, 59, 59}, {24, 0, 0}, {12, 60, 0}, {12, 0, 60}} {
					s := fmt.Sprintf("%02d/%s/%04d:%02d:%02d:%02d", day, mon, year, hms[0], hms[1], hms[2])
					want, err := time.Parse(layout, s)
					got := parseTimestamp([]byte(s), 0, len(s))
					if err != nil {
						if !got.IsZero() {
							t.Errorf("%q: time.Parse rejects (%v) but parseTimestamp = %v", s, err, got)
						}
						continue
					}
					if !got.Equal(want) {
						t.Errorf("%q: parseTimestamp = %v, time.Parse = %v", s, got, want)
					}
				}
			}
		}
	}
}
