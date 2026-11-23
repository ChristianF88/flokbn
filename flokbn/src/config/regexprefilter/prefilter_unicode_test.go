package regexprefilter

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// C7: Go's (?i) folds with Unicode simple case folding, so an ASCII 's' also
// matches U+017F (LATIN SMALL LETTER LONG S) and an ASCII 'k' also matches
// U+212A (KELVIN SIGN). The screen folded ASCII only and rejected such inputs
// without consulting the regex - a false negative. The tests below use the
// package constants longS and kelvinSign for those two runes.

// assertGateEqualsRegex checks the two invariants for one (pattern, input):
// necessity (a regex match is never screened out) and gate equality (the
// screen-then-regex gate used by config.regexGate equals the plain regex).
func assertGateEqualsRegex(t *testing.T, pat, in string) {
	t.Helper()
	re := regexp.MustCompile(pat)
	pf := Build(pat)
	want := re.MatchString(in)
	if want && pf != nil && !pf.MightMatch(in) {
		t.Errorf("NECESSITY VIOLATED pattern=%q input=%q: regex matched but MightMatch=false (pf=%+v)", pat, in, pf)
	}
	if got := evalGate(re, pf, in); got != want {
		t.Errorf("gate mismatch pattern=%q input=%q gate=%v want=%v (pf=%+v)", pat, in, got, want, pf)
	}
}

func TestUnicodeFoldOfAsciiLetters(t *testing.T) {
	patterns := []string{
		`(?i)sqlmap`,
		`(?i)nikto`,
		`(?i)(bot|crawl|spider|python-requests|curl|wget|nikto|sqlmap|scan|masscan|Mobile)`,
		`(?i)(/search|/tasks|/api)`,
		`(?i)task/\d+`,
		`(?i:scan)ner`,
		`(?i)K`, // too short for a needle; must stay correct via the regex
		`(?i)` + kelvinSign + `ali`,
		`(?i)ma` + longS + longS + `can`,
		`sqlmap`, // case-sensitive: the long s must NOT match
		`(SQL|(?i:map))`,
	}
	inputs := []string{
		longS + "qlmap",
		"x " + longS + "QLMAP/1.0",
		"ni" + kelvinSign + "to",
		"NI" + kelvinSign + "TO scanner",
		"ma" + longS + longS + "can",
		"MA" + longS + "Scan",
		"ta" + longS + kelvinSign + "/42",
		"/ta" + longS + kelvinSign + longS,
		"/" + longS + "earch?q=1",
		longS + "pider",
		longS + "canner",
		kelvinSign + "ali",
		kelvinSign,
		// contain the special runes but do not match
		longS + " only",
		"Kelvin " + kelvinSign + " sign",
		longS + "qlma",
		"sqlma" + longS,
		"ni" + kelvinSign + "t",
		// other multi-byte text sharing the lead bytes 0xC5 / 0xE2
		"ő and “quoted” …",
		"sqlmap “quoted”",
		// truncated / invalid encodings of the special runes
		"\xc5qlmap",
		"ni\xe2\x84to",
		"\xbfqlmap",
		"",
	}
	for _, pat := range patterns {
		for _, in := range inputs {
			assertGateEqualsRegex(t, pat, in)
		}
	}
}

// The exact patterns must stay exact (no regex call on the hot path) and the
// screen alone must equal the regex on the special runes.
func TestUnicodeFoldKeepsExactness(t *testing.T) {
	for _, pat := range []string{`(?i)sqlmap`, `(?i)(bot|spider|nikto)`} {
		pf := Build(pat)
		if pf == nil || !pf.Exact() {
			t.Fatalf("Build(%q) should stay an exact prefilter, got %+v", pat, pf)
		}
	}
	pf := Build(`(?i)sqlmap`)
	if !pf.MightMatch(longS + "qlmap") {
		t.Errorf("(?i)sqlmap must accept %q", longS+"qlmap")
	}
	if pf.MightMatch(longS + "qlma") {
		t.Errorf("(?i)sqlmap is exact and must reject %q", longS+"qlma")
	}
}

// The fix relies on U+017F and U+212A being the ONLY non-ASCII runes in the
// simple-fold orbit of an ASCII letter. Pin that against the Unicode tables of
// the toolchain so a future table change fails here instead of silently
// reintroducing false negatives.
func TestAsciiLetterFoldOrbits(t *testing.T) {
	for c := 'a'; c <= 'z'; c++ {
		var extra []rune
		for r := unicode.SimpleFold(c); r != c; r = unicode.SimpleFold(r) {
			if r > unicode.MaxASCII {
				extra = append(extra, r)
			}
		}
		var want []rune
		switch c {
		case 's':
			want = []rune{0x17F}
		case 'k':
			want = []rune{0x212A}
		}
		if string(extra) != string(want) {
			t.Errorf("fold orbit of %q has non-ASCII members %U, want %U", c, extra, want)
		}
	}
}

// A case-sensitive non-ASCII literal next to a folded ASCII literal: the
// needle was lowercased with the Unicode-aware strings.ToLower while matching
// folds ASCII only, so the upper-case non-ASCII rune could never be found.
func TestMixedFoldKeepsNonASCIIBytes(t *testing.T) {
	patterns := []string{
		"(?i:bot)É",       // É stays case-sensitive
		"É(?i:bot)",       //
		"(?i:scan)İx",     // U+0130 lowercases to a 2-rune sequence
		"(?i:bot)É|other", //
	}
	inputs := []string{
		"botÉ", "BOTÉ", "BotÉ tail", "boté", "BOTé",
		"Ébot", "ÉBOT", "ébot",
		"scanİx", "SCANİx", "scani̇x", "other", "",
	}
	for _, pat := range patterns {
		for _, in := range inputs {
			assertGateEqualsRegex(t, pat, in)
		}
	}
}

// U+FFFD in a pattern matches ANY invalid UTF-8 byte in the input (the regex
// engine decodes each as U+FFFD), which a byte-substring needle cannot express.
func TestReplacementCharLiteral(t *testing.T) {
	patterns := []string{"ab�", "(?i)bot�", "��"}
	inputs := []string{"ab\xff", "ab�", "BOT\xc5", "bot�", "\xff\xfe", "abc", ""}
	for _, pat := range patterns {
		for _, in := range inputs {
			assertGateEqualsRegex(t, pat, in)
		}
	}
}

// Randomized differential run with inputs that swap ASCII s/k for their
// non-ASCII fold partners and sprinkle other multi-byte runes.
func TestPrefilterRandomRegexUnicodeInputs(t *testing.T) {
	patterns := 3000
	inputsPer := 40
	if testing.Short() {
		patterns = 300
		inputsPer = 12
	}
	rng := rand.New(rand.NewSource(0x17F212A))
	swap := func(in string) string {
		var b strings.Builder
		for _, r := range in {
			switch {
			case (r == 's' || r == 'S') && rng.Intn(2) == 0:
				b.WriteString(longS)
			case (r == 'k' || r == 'K') && rng.Intn(2) == 0:
				b.WriteString(kelvinSign)
			case rng.Intn(12) == 0:
				b.WriteString("“")
				b.WriteRune(r)
			default:
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	tokens := append([]string{"task", "sk", "ks", "ssh", "kiosk"}, randTokens...)
	for p := 0; p < patterns; p++ {
		pat := randomPatternFrom(rng, tokens, 0)
		re, err := regexp.Compile(pat)
		if err != nil {
			continue
		}
		pf := Build(pat)
		for i := 0; i < inputsPer; i++ {
			var b strings.Builder
			for n := rng.Intn(6); n > 0; n-- {
				tok := tokens[rng.Intn(len(tokens))]
				if rng.Intn(2) == 0 {
					tok = strings.ToUpper(tok)
				}
				b.WriteString(tok)
			}
			in := swap(b.String())
			want := re.MatchString(in)
			if want && pf != nil && !pf.MightMatch(in) {
				t.Fatalf("NECESSITY VIOLATED pattern=%q input=%q: regex matched but MightMatch=false (pf=%+v)", pat, in, pf)
			}
			if got := evalGate(re, pf, in); got != want {
				t.Fatalf("gate mismatch pattern=%q input=%q gate=%v want=%v (pf=%+v)", pat, in, got, want, pf)
			}
		}
	}
}

// randomPatternFrom is randomPattern over a caller-supplied token alphabet.
func randomPatternFrom(rng *rand.Rand, tokens []string, depth int) string {
	tok := func() string { return regexp.QuoteMeta(tokens[rng.Intn(len(tokens))]) }
	if depth > 3 {
		return tok()
	}
	sub := func() string { return randomPatternFrom(rng, tokens, depth+1) }
	switch rng.Intn(8) {
	case 0, 1:
		return tok()
	case 2:
		return "(" + sub() + "|" + sub() + ")"
	case 3:
		return sub() + sub()
	case 4:
		return "(" + sub() + ")+"
	case 5:
		return "(" + sub() + ")?"
	case 6:
		return "(?i)" + sub()
	default:
		return "(?i:" + sub() + ")"
	}
}
