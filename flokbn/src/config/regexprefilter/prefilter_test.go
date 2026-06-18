package regexprefilter

import (
	"fmt"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// sortedNeedles returns a sorted copy of a prefilter's needles for stable
// comparison in tests.
func sortedNeedles(p *Prefilter) []string {
	if p == nil {
		return nil
	}
	out := append([]string(nil), p.needles...)
	sort.Strings(out)
	return out
}

// TestExtractRequiredLiterals asserts the precise needle set, foldCase, and
// exact flag for canonical patterns. This catches regressions such as picking
// "b" instead of "bot".
func TestExtractRequiredLiterals(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantNil bool
		needles []string // sorted; ignored when wantNil
		fold    bool
		exact   bool
	}{
		{
			name:    "pure literal alternation",
			pattern: `(bot|crawl|spider)`,
			needles: []string{"bot", "crawl", "spider"},
			fold:    false,
			exact:   true,
		},
		{
			name:    "case-insensitive bot list",
			pattern: `(?i)(bot|crawl|spider|python-requests|curl|wget|nikto|sqlmap|scan|masscan|Mobile)`,
			needles: []string{"bot", "crawl", "curl", "masscan", "mobile", "nikto", "python-requests", "scan", "spider", "sqlmap", "wget"},
			fold:    true,
			exact:   true,
		},
		{
			name:    "endpoint list",
			pattern: `(?i)(/dataset|/psi|/islandora|/search|/admin|/api)`,
			needles: []string{"/admin", "/api", "/dataset", "/islandora", "/psi", "/search"},
			fold:    true,
			exact:   true,
		},
		{
			name:    "single literal",
			pattern: `bot`,
			needles: []string{"bot"},
			fold:    false,
			exact:   true,
		},
		{
			name:    "concat with literal and digits is necessary screen not exact",
			pattern: `(?i)bot/\d+`,
			needles: []string{"bot/"},
			fold:    true,
			exact:   false,
		},
		{
			name:    "anchored prefix yields literal but not exact",
			pattern: `^Mozilla`,
			needles: []string{"Mozilla"},
			fold:    false,
			exact:   false,
		},
		{
			name:    "anchored suffix yields literal but not exact",
			pattern: `bot$`,
			needles: []string{"bot"},
			fold:    false,
			exact:   false,
		},
		{
			name:    "ab*c requires a and c not b",
			pattern: `ab*c`,
			// concat picks the longest single literal; a and c are each 1 byte,
			// b* contributes nothing. Both surviving literals are <2 bytes so
			// Build bails.
			wantNil: true,
		},
		{
			name:    " xby* requires xb",
			pattern: `xby*z`,
			needles: []string{"xb"},
			exact:   false,
		},
		{
			name:    "colou?r required colo and r, picks colo",
			pattern: `colou?r`,
			needles: []string{"colo"},
			exact:   false,
		},
		{
			name:    "(abc)?def requires def",
			pattern: `(abc)?def`,
			needles: []string{"def"},
			exact:   false,
		},
		{
			name:    "nested alternation literal",
			pattern: `((Google|Bing)bot)`,
			// The extractor cross-products the (Google|Bing) alternation with
			// the "bot" suffix, yielding the exact OR-set {Googlebot, Bingbot}.
			// This is provably equivalent to "contains one of them" -> exact.
			needles: []string{"Bingbot", "Googlebot"},
			exact:   true,
		},
		{
			name:    "heterogeneous-fold alternation is not exact",
			pattern: `(BOT|(?i:spider))`,
			// BOT is case-sensitive, (?i:spider) is folded. The set is lowercased
			// uniformly under one global foldCase, which makes MightMatch
			// case-insensitive for the BOT branch too -> over-permissive, so the
			// tree must NOT claim exact and must defer to the real regex.
			needles: []string{"bot", "spider"},
			fold:    true,
			exact:   false,
		},
		{
			name:    "uniform-fold alternation stays exact (control)",
			pattern: `(?i:bot|spider)`,
			needles: []string{"bot", "spider"},
			fold:    true,
			exact:   true,
		},
		{
			name:    "no-fold alternation stays exact (control)",
			pattern: `(BOT|CRAWL)`,
			needles: []string{"BOT", "CRAWL"},
			fold:    false,
			exact:   true,
		},
		{
			name:    "heterogeneous-fold concat is not exact",
			pattern: `BOT(?i:x)`,
			// Cross-products to "BOTx", lowercased to "botx" under global
			// foldCase; case-insensitive on the BOT span -> over-permissive, so
			// not exact. Needle "botx" is >= minLiteralLen so it survives.
			needles: []string{"botx"},
			fold:    true,
			exact:   false,
		},
		{
			name:    "nested heterogeneous-fold run is not exact",
			pattern: `((Google|(?i:bing))bot)`,
			// (Google|(?i:bing)) is a heterogeneous-fold alternation, so the run
			// gluing it with "bot" must not be reported as full -> not exact.
			needles: []string{"googlebot", "bingbot"},
			fold:    true,
			exact:   false,
		},
		{
			name:    "uniform-fold concat stays exact (control)",
			pattern: `(?i:bot)(?i:x)`,
			needles: []string{"botx"},
			fold:    true,
			exact:   true,
		},
		{
			name:    "no-fold concat stays exact (control)",
			pattern: `BOT(x)`,
			needles: []string{"BOTx"},
			fold:    false,
			exact:   true,
		},
		{
			name:    "alternation with dotstar branch bails",
			pattern: `(foo|.*)`,
			wantNil: true,
		},
		{
			name:    "alternation with charclass branch bails",
			pattern: `(bot|[a-z]+)`,
			wantNil: true,
		},
		{
			name:    "dotstar bails",
			pattern: `.*`,
			wantNil: true,
		},
		{
			name:    "charclass plus bails",
			pattern: `[a-z]+`,
			wantNil: true,
		},
		{
			name:    "digit repeat bails",
			pattern: `\d{3}`,
			wantNil: true,
		},
		{
			name:    "empty anchor bails",
			pattern: `^$`,
			wantNil: true,
		},
		{
			name:    "non-ascii fold bails",
			pattern: `(?i)café`,
			wantNil: true,
		},
		{
			name:    "single byte literal bails",
			pattern: `a`,
			wantNil: true,
		},
		{
			name:    "empty pattern bails",
			pattern: ``,
			wantNil: true,
		},
		{
			name:    "plus on literal keeps it",
			pattern: `(abc)+`,
			needles: []string{"abc"},
			exact:   false,
		},
		{
			name:    "repeat min 2 keeps child",
			pattern: `(ab){2,4}`,
			needles: []string{"ab"},
			exact:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := Build(tt.pattern)
			if tt.wantNil {
				if pf != nil {
					t.Fatalf("Build(%q) = %+v, want nil", tt.pattern, pf)
				}
				return
			}
			if pf == nil {
				t.Fatalf("Build(%q) = nil, want needles %v", tt.pattern, tt.needles)
			}
			got := sortedNeedles(pf)
			want := append([]string(nil), tt.needles...)
			sort.Strings(want)
			if !equalStrings(got, want) {
				t.Errorf("Build(%q) needles = %v, want %v", tt.pattern, got, want)
			}
			if pf.foldCase != tt.fold {
				t.Errorf("Build(%q) foldCase = %v, want %v", tt.pattern, pf.foldCase, tt.fold)
			}
			if pf.Exact() != tt.exact {
				t.Errorf("Build(%q) exact = %v, want %v", tt.pattern, pf.Exact(), tt.exact)
			}
		})
	}
}

// evalGate mirrors the production gate in config.go's regexGate: when the
// prefilter is nil the regex runs directly; otherwise the prefilter screens
// first and, unless it is exact, the regex confirms.
func evalGate(re *regexp.Regexp, pf *Prefilter, s string) bool {
	if pf == nil {
		return re.MatchString(s)
	}
	if !pf.MightMatch(s) {
		return false
	}
	if pf.Exact() {
		return true
	}
	return re.MatchString(s)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestMightMatch exercises the screen directly: fold/non-fold, single/multi,
// overlapping needles, and empty input.
func TestMightMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		{"single nonfold present", `bot`, "googlebot/2.1", true},
		{"single nonfold absent", `bot`, "Mozilla/5.0", false},
		{"single nonfold empty input", `bot`, "", false},
		{"multi nonfold present middle", `(bot|crawl)`, "a crawl b", true},
		{"multi nonfold absent", `(bot|crawl)`, "nothing here", false},
		{"fold mixed case present", `(?i)bot`, "GoogleBoT", true},
		{"fold upper present", `(?i)bot`, "BOT", true},
		{"fold absent", `(?i)bot`, "spider", false},
		{"overlap scan in masscan", `(?i)(scan|masscan)`, "masscanner", true},
		{"overlap scan not in mass", `(?i)(scan|masscan)`, "mass only", false},
		{"token at start", `(?i)(scan)`, "scanner here", true},
		{"token at end", `(?i)(scan)`, "long string ending scan", true},
		{"fold empty input", `(?i)bot`, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pf := Build(tt.pattern)
			if pf == nil {
				t.Fatalf("Build(%q) returned nil", tt.pattern)
			}
			if got := pf.MightMatch(tt.input); got != tt.want {
				t.Errorf("MightMatch(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// differentialPatterns is the table of patterns used by the differential test
// and as fuzz seeds.
var differentialPatterns = []string{
	`(bot|crawl|spider)`,
	`(?i)(bot|crawl|spider|python-requests|curl|wget|nikto|sqlmap|scan|masscan|Mobile)`,
	`(?i)(/dataset|/psi|/islandora|/search|/admin|/api)`,
	`(?i)bot/\d+`,
	`(foo|.*)`,
	`(bot|[a-z]+)`,
	`^Mozilla`,
	`bot$`,
	`^$`,
	`[a-z]+`,
	`.*`,
	`\d{3}`,
	`ab*c`,
	`colou?r`,
	`(abc)?def`,
	`((Google|Bing)bot)`,
	`(?i)café`,
	``,
	`bot`,
	`(?i)(scan|masscan)`,
	`xby*z`,
	// Heterogeneous case-fold patterns (AUDIT-01): a case-sensitive branch/child
	// mixed with a scoped (?i:...) one. These must defer to the real regex.
	`(BOT|(?i:spider))`,
	`BOT(?i:x)`,
	`((Google|(?i:bing))bot)`,
	`(?i:bot|spider)`,
}

// differentialInputs is a large corpus covering token placement, overlapping
// needles, mixed case, empties, and long strings.
var differentialInputs = []string{
	"",
	"bot",
	"BOT",
	"BoT",
	"googlebot/2.1 (+http://www.google.com/bot.html)",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	"masscanner",
	"mass only no token",
	"scan at start",
	"ends with scan",
	"a crawl in the middle",
	"python-requests/2.28.1",
	"curl/7.68.0",
	"wget/1.20",
	"nikto scanner",
	"sqlmap/1.5",
	"Mobile Safari",
	"/dataset/123",
	"/psi/foo",
	"/islandora/object/1",
	"/search?q=x",
	"/admin/login",
	"/api/v1/users",
	"/home/index.html",
	"colour",
	"color",
	"colouur",
	"def here",
	"abcdef",
	"Googlebot",
	"Bingbot",
	"café latte",
	"CAFÉ",
	"xbz",
	"xbyyyz",
	"xz",
	"123",
	"a1b2c3",
	strings.Repeat("x", 150) + "bot",
	strings.Repeat("Mozilla compatible ", 8) + "spider",
	strings.Repeat("/static/asset ", 10),
	"ac",
	"abbbc",
	// Case variants that distinguish case-sensitive vs folded branches
	// (AUDIT-01): "bot"/"botx" must be REJECTED by (BOT|...) / BOT(?i:x) but the
	// folded "spider"/"x" half stays case-insensitive.
	"spider",
	"SPIDER",
	"botx",
	"BOTx",
	"BOTX",
	"bingbot",
	"Googlebot",
}

// TestPrefilterDifferential asserts that the prefilter gate is identical to the
// plain regex for every (pattern, input), and that the necessity invariant
// holds (regex match => MightMatch).
func TestPrefilterDifferential(t *testing.T) {
	for _, pat := range differentialPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			t.Fatalf("regexp.Compile(%q): %v", pat, err)
		}
		pf := Build(pat)
		for _, in := range differentialInputs {
			want := re.MatchString(in)
			// Model the real config.go gate: a nil prefilter runs the regex
			// directly; otherwise screen then (if not exact) run the regex.
			gate := evalGate(re, pf, in)
			if gate != want {
				t.Errorf("gate mismatch pattern=%q input=%q gate=%v want=%v (pf=%+v)", pat, in, gate, want, pf)
			}
			// Necessity invariant: a true match must always pass the prefilter.
			if want && pf != nil && !pf.MightMatch(in) {
				t.Errorf("NECESSITY VIOLATED pattern=%q input=%q: regex matched but MightMatch=false (pf=%+v)", pat, in, pf)
			}
		}
	}
}

// TestHeterogeneousFoldGate is the targeted regression test for AUDIT-01: a
// pattern mixing a case-sensitive branch/child with a scoped case-insensitive
// one must defer to the authoritative regex (never claim exact), and the gate
// result must equal regexp.MatchString for every input including case variants.
func TestHeterogeneousFoldGate(t *testing.T) {
	patterns := []string{
		`(BOT|(?i:spider))`,
		`BOT(?i:x)`,
		`((Google|(?i:bing))bot)`,
		`((?i:Google)|Bing)bot`,
	}
	inputs := []string{
		"", "bot", "BOT", "BoT",
		"spider", "SPIDER", "Spider",
		"botx", "BOTx", "BOTX", "botX",
		"googlebot", "Googlebot", "GOOGLEBOT",
		"bingbot", "Bingbot", "BINGBOT",
		"a googlebot here", "the BOT crawls", "scan SPIDER scan",
	}
	for _, pat := range patterns {
		re := regexp.MustCompile(pat)
		pf := Build(pat)
		if pf == nil {
			t.Fatalf("Build(%q) = nil, want a prefilter", pat)
		}
		if pf.Exact() {
			t.Errorf("Build(%q).Exact() = true, want false (heterogeneous fold must defer to regex)", pat)
		}
		for _, in := range inputs {
			want := re.MatchString(in)
			gate := evalGate(re, pf, in)
			if gate != want {
				t.Errorf("gate mismatch pattern=%q input=%q gate=%v want=%v (pf=%+v)", pat, in, gate, want, pf)
			}
			// Necessity must still hold: a real match always passes the screen.
			if want && !pf.MightMatch(in) {
				t.Errorf("NECESSITY VIOLATED pattern=%q input=%q: regex matched but MightMatch=false (pf=%+v)", pat, in, pf)
			}
		}
	}
}

// TestPrefilterRandomRegex generates seeded random regexes and inputs and
// asserts the necessity invariant. It also checks the full gate equality.
func TestPrefilterRandomRegex(t *testing.T) {
	patterns := 4000
	inputsPer := 40
	if testing.Short() {
		patterns = 300
		inputsPer = 12
	}
	rng := rand.New(rand.NewSource(0xC1D8E))
	for p := 0; p < patterns; p++ {
		pat := randomPattern(rng, 0)
		re, err := regexp.Compile(pat)
		if err != nil {
			continue
		}
		pf := Build(pat)
		for i := 0; i < inputsPer; i++ {
			in := randomInput(rng)
			want := re.MatchString(in)
			if want && pf != nil && !pf.MightMatch(in) {
				t.Fatalf("NECESSITY VIOLATED pattern=%q input=%q: regex matched but MightMatch=false (pf=%+v)", pat, in, pf)
			}
			gate := evalGate(re, pf, in)
			if gate != want {
				t.Fatalf("gate mismatch pattern=%q input=%q gate=%v want=%v (pf=%+v)", pat, in, gate, want, pf)
			}
		}
	}
}

// alphabet used by the random grammar, kept small so tokens overlap and the
// prefilter is exercised on near-misses.
var randTokens = []string{"a", "b", "ab", "bot", "scan", "mass", "/x", "/api", "0", "1"}

// randomPattern builds a random Perl-syntax regex string. depth limits
// recursion. It mixes literals, char classes, alternation, concatenation,
// quantifiers, anchors and the (?i) flag.
func randomPattern(rng *rand.Rand, depth int) string {
	if depth > 3 {
		return regexp.QuoteMeta(randTokens[rng.Intn(len(randTokens))])
	}
	switch rng.Intn(10) {
	case 0:
		return regexp.QuoteMeta(randTokens[rng.Intn(len(randTokens))])
	case 1: // char class
		classes := []string{`[a-z]`, `[abc]`, `\d`, `[0-9]`, `[A-Z]`, `[xy]`}
		return classes[rng.Intn(len(classes))]
	case 2: // alternation
		n := 2 + rng.Intn(2)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = randomPattern(rng, depth+1)
		}
		return "(" + strings.Join(parts, "|") + ")"
	case 3: // concat
		n := 2 + rng.Intn(2)
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(randomPattern(rng, depth+1))
		}
		return b.String()
	case 4: // star
		return "(" + randomPattern(rng, depth+1) + ")*"
	case 5: // plus
		return "(" + randomPattern(rng, depth+1) + ")+"
	case 6: // quest
		return "(" + randomPattern(rng, depth+1) + ")?"
	case 7: // anchored
		anc := []string{"^", "$"}
		return anc[rng.Intn(len(anc))] + randomPattern(rng, depth+1)
	case 8: // whole-pattern case-insensitive wrap
		return "(?i)" + randomPattern(rng, depth+1)
	default: // scoped case-insensitive group -> exercises heterogeneous fold
		return "(?i:" + randomPattern(rng, depth+1) + ")"
	}
}

// randomInput produces a random string from the same token alphabet plus some
// noise and mixed case.
func randomInput(rng *rand.Rand) string {
	n := rng.Intn(8)
	var b strings.Builder
	for i := 0; i < n; i++ {
		t := randTokens[rng.Intn(len(randTokens))]
		if rng.Intn(2) == 0 {
			t = strings.ToUpper(t)
		}
		b.WriteString(t)
	}
	return b.String()
}

// FuzzPrefilterEquivalence is the native Go fuzzer for the necessity invariant.
func FuzzPrefilterEquivalence(f *testing.F) {
	for _, pat := range differentialPatterns {
		for _, in := range differentialInputs {
			f.Add(pat, in)
		}
	}
	f.Fuzz(func(t *testing.T, pat, input string) {
		re, err := regexp.Compile(pat)
		if err != nil {
			return
		}
		pf := Build(pat)
		if pf == nil {
			return
		}
		if re.MatchString(input) && !pf.MightMatch(input) {
			t.Fatalf("NECESSITY VIOLATED pattern=%q input=%q: regex matched but MightMatch=false (pf=%+v)", pat, input, pf)
		}
		// When exact, MightMatch must equal the regex exactly.
		if pf.Exact() {
			if pf.MightMatch(input) != re.MatchString(input) {
				t.Fatalf("EXACT MISMATCH pattern=%q input=%q: MightMatch=%v regex=%v", pat, input, pf.MightMatch(input), re.MatchString(input))
			}
		}
	})
}

// ensure fmt import is used (helpful diagnostics in failures elsewhere).
var _ = fmt.Sprintf
