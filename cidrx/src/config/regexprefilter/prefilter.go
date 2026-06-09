// Package regexprefilter builds a cheap required-literal prefilter for a
// user-supplied regular expression, modeled on the "required literal" screen
// that ripgrep / the Rust regex crate use to avoid stepping the full automaton
// over every byte of long non-matching inputs.
//
// The prefilter is a NECESSARY condition for a regex match: for every input s,
//
//	regex.MatchString(s) == true  =>  Prefilter.MightMatch(s) == true
//
// so the gate `pf.MightMatch(s) && regex.MatchString(s)` is identical to
// `regex.MatchString(s)` for every input. The prefilter may report a false
// positive (MightMatch true while the regex does not match); the authoritative
// regex then rejects it. The prefilter MUST NOT report a false negative — that
// would silently drop a matching request, which is data corruption.
//
// When a pattern is provably equivalent to "the input contains one of these
// literal substrings" (an unanchored pure-literal alternation, optionally
// case-insensitive), Build marks the prefilter Exact, and callers may skip the
// regex entirely. This is the common bot/endpoint case and yields the large
// speedup.
//
// The extractor is deliberately conservative and FAILS CLOSED: any op it does
// not fully understand, any branch of an alternation without a required
// literal, or any non-ASCII case-folding, causes Build to return nil. A nil
// prefilter means "no screening possible" and the caller falls back to running
// the regex directly. Build never panics and never returns an error.
//
// A built Prefilter is immutable and therefore safe to share across goroutines
// without locking.
package regexprefilter

import (
	"regexp/syntax"
	"strings"
)

// Prefilter screens inputs with a cheap multi-substring test before the full
// regex runs. The zero value is not usable; obtain one from Build.
type Prefilter struct {
	// needles holds the required-literal OR-set: a matching input must contain
	// at least one of these substrings. When foldCase is true the needles are
	// stored ASCII-lowercased and matched case-insensitively.
	needles []string
	// foldCase reports whether matching is ASCII case-insensitive.
	foldCase bool
	// exact reports whether MightMatch alone is equivalent to the regex, so the
	// caller may skip the regex call entirely.
	exact bool
}

// Exact reports whether MightMatch is provably equivalent to the source
// regex's MatchString, meaning the caller may skip the regex call.
func (p *Prefilter) Exact() bool { return p.exact }

// minLiteralLen is the shortest literal we keep. Single-byte needles screen out
// almost nothing on real traffic, so they are dropped; if a required-literal
// set ends up empty after this filter, Build bails (returns nil).
const minLiteralLen = 2

// Build analyzes pattern and returns a Prefilter that is a necessary condition
// for the pattern matching (unanchored, as regexp.MatchString does). It returns
// nil when no useful required literal can be extracted, in which case the
// caller must run the regex directly. Build never errors and never panics; it
// fails closed (nil) on anything it cannot prove safe.
func Build(pattern string) *Prefilter {
	if pattern == "" {
		return nil
	}
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}

	lits, fold, ok := requiredLiterals(re)
	if !ok || len(lits) == 0 {
		return nil
	}

	// Drop literals shorter than minLiteralLen (measured in bytes). If nothing
	// long enough survives, the screen would be too weak / unsafe — bail.
	kept := lits[:0]
	for _, l := range lits {
		if len(l) >= minLiteralLen {
			kept = append(kept, l)
		} else {
			// A surviving literal shorter than the threshold means we cannot
			// keep the OR-set complete (every branch of an alternation must
			// contribute). Dropping it would break necessity, so bail.
			return nil
		}
	}
	if len(kept) == 0 {
		return nil
	}

	if fold {
		for i := range kept {
			kept[i] = strings.ToLower(kept[i])
		}
	}
	kept = dedup(kept)

	// The pattern is provably equivalent to "contains one of {literals}" under
	// unanchored MatchString exactly when the top-level node matches its whole
	// span as one of the literals (full) — i.e. there is no anchor, repetition,
	// or surrounding structure that MightMatch would ignore. Because Build bails
	// when any required literal is shorter than the threshold, reaching this
	// point guarantees no needle was dropped, so full => exact is sound.
	topRes := extract(re)
	exact := topRes.ok && topRes.full

	return &Prefilter{
		needles:  kept,
		foldCase: fold,
		exact:    exact,
	}
}

// dedup removes duplicate needles in place-ish (returns a new compact slice).
func dedup(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// maxCrossProduct bounds the size of the literal OR-set we are willing to build
// when cross-multiplying concatenated alternations. Beyond this we fall back to
// the best required substring (still correct, just a weaker screen).
const maxCrossProduct = 64

// litResult is the internal extractor result for a node.
//
//	set  : an OR-set of literals. Necessity invariant — if the node matches a
//	       span, that span contains at least one member of set as a substring.
//	full : true iff the node matches EXACTLY one of the members of set and
//	       nothing else (i.e. the node's whole matched text is a member). This
//	       lets a concatenation glue adjacent children together exactly. When
//	       full is false the members are only guaranteed-contained substrings.
//	fold : true iff any member was case-folded (screen must be ASCII-insensitive).
//	ok   : false means "no required literal" (fail closed).
type litResult struct {
	set  []string
	full bool
	fold bool
	ok   bool
}

func failClosed() litResult { return litResult{ok: false} }

// requiredLiterals is the public-ish wrapper returning the OR-set + fold flag.
func requiredLiterals(re *syntax.Regexp) (lits []string, fold bool, ok bool) {
	r := extract(re)
	if !r.ok || len(r.set) == 0 {
		return nil, false, false
	}
	return r.set, r.fold, true
}

// extract recursively computes the litResult for re.
func extract(re *syntax.Regexp) litResult {
	switch re.Op {
	case syntax.OpLiteral:
		l, f, lok := literalFromRunes(re.Rune, re.Flags)
		if !lok {
			return failClosed()
		}
		return litResult{set: []string{l}, full: true, fold: f, ok: true}

	case syntax.OpCharClass:
		// Exactly-one-rune class behaves like a one-rune literal (full match).
		if len(re.Rune) == 2 && re.Rune[0] == re.Rune[1] {
			l, f, lok := literalFromRunes(re.Rune[:1], re.Flags)
			if !lok {
				return failClosed()
			}
			return litResult{set: []string{l}, full: true, fold: f, ok: true}
		}
		// Multi-rune class: no required literal, but it is a "matched span" of
		// some single character — represented as not-ok (contributes nothing).
		return failClosed()

	case syntax.OpPlus:
		// x+ requires one x. The child's required substring is required; but the
		// span is no longer a single exact literal, so full=false.
		r := extract(re.Sub[0])
		if !r.ok {
			return failClosed()
		}
		r.full = false
		return r

	case syntax.OpRepeat:
		if re.Min >= 1 {
			r := extract(re.Sub[0])
			if !r.ok {
				return failClosed()
			}
			r.full = false
			return r
		}
		return failClosed()

	case syntax.OpCapture:
		// A plain capture group does not change what is matched.
		return extract(re.Sub[0])

	case syntax.OpAlternate:
		// Every branch must contribute a required literal; otherwise some
		// matching input might contain none of our needles. Bail if any branch
		// yields nothing. The result is the union of all branches' sets. The
		// alternation is "full" only if every branch is itself full (each
		// branch matches exactly one literal), enabling exact concatenation.
		var all []string
		anyFold := false
		allFull := true
		for _, sub := range re.Sub {
			r := extract(sub)
			if !r.ok || len(r.set) == 0 {
				return failClosed()
			}
			all = append(all, r.set...)
			anyFold = anyFold || r.fold
			allFull = allFull && r.full
		}
		return litResult{set: all, full: allFull, fold: anyFold, ok: true}

	case syntax.OpConcat:
		return extractConcat(re.Sub)

	case syntax.OpStar, syntax.OpQuest:
		// May match zero times: nothing required.
		return failClosed()

	case syntax.OpAnyChar, syntax.OpAnyCharNotNL,
		syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary,
		syntax.OpEmptyMatch, syntax.OpNoMatch:
		return failClosed()

	default:
		// Unknown / unhandled op: fail closed. NEVER guess.
		return failClosed()
	}
}

// extractConcat computes the required-literal set for a concatenation of subs.
//
// It scans children left to right, maintaining the "current run": a set of
// literals that are contiguously required (every match contains one of them as
// a contiguous substring) built from adjacent FULL children by cross product.
// When a child breaks the run (it is not ok, or not full), the run is closed
// off as a completed candidate and a new run begins after it. At the end the
// best completed run (the one whose SHORTEST member is longest — strongest
// rejection) becomes the result. The whole concat is "full" only if it reduced
// to a single uninterrupted run spanning every child.
func extractConcat(subs []*syntax.Regexp) litResult {
	var bestRun []string
	bestFold := false
	bestMin := -1 // shortest member length of bestRun

	var cur []string // current run's cross-product set; nil = empty run
	curFold := false
	curFull := true // does the run so far consist solely of FULL children?
	runSpansAll := false
	sawAnyChild := false

	closeRun := func() {
		if len(cur) == 0 {
			return
		}
		m := minLen(cur)
		if m > bestMin {
			bestMin = m
			bestRun = cur
			bestFold = curFold
		}
		cur = nil
		curFold = false
		curFull = true
	}

	for i, sub := range subs {
		r := extract(sub)
		sawAnyChild = true
		if !r.ok || len(r.set) == 0 {
			// Child contributes no literal (charclass+, star, anychar, ...).
			// It breaks the contiguous run.
			closeRun()
			runSpansAll = false
			continue
		}
		if len(cur) == 0 {
			// Start a new run with this child's set.
			cur = append([]string(nil), r.set...)
			curFold = r.fold
			curFull = r.full
			if i == 0 {
				runSpansAll = true
			} else {
				runSpansAll = false
			}
		} else if curFull && r.full {
			// Glue exactly: cross-product the current run with this child.
			next := crossProduct(cur, r.set)
			if next == nil {
				// Product too large: close the current run and start fresh.
				closeRun()
				cur = append([]string(nil), r.set...)
				curFold = r.fold
				curFull = r.full
				runSpansAll = false
			} else {
				cur = next
				curFold = curFold || r.fold
				curFull = r.full
			}
		} else {
			// Current run is not exact-gluable (a + or similar produced a
			// substring set, not a full span). Keep the longer of the two as a
			// completed candidate; do not glue across a non-full boundary.
			closeRun()
			cur = append([]string(nil), r.set...)
			curFold = r.fold
			curFull = r.full
			runSpansAll = false
		}
		// If this child was not full, the run cannot continue exactly past it.
		if !r.full {
			closeRun()
			runSpansAll = false
		}
	}
	closeRun()

	if !sawAnyChild || len(bestRun) == 0 {
		return failClosed()
	}
	return litResult{set: bestRun, full: runSpansAll, fold: bestFold, ok: true}
}

// crossProduct returns every a+b concatenation, or nil if the product would
// exceed maxCrossProduct.
func crossProduct(a, b []string) []string {
	if len(a)*len(b) > maxCrossProduct {
		return nil
	}
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			out = append(out, x+y)
		}
	}
	return out
}

func minLen(ss []string) int {
	m := -1
	for _, s := range ss {
		if m < 0 || len(s) < m {
			m = len(s)
		}
	}
	return m
}

// literalFromRunes converts a rune slice from an OpLiteral (or single-rune
// OpCharClass) into a byte literal. It honors case folding: if flags request
// FoldCase, fold is reported true. It fails closed (ok==false) when folding is
// requested for a non-ASCII rune, because Unicode case folding can map runes to
// sequences of different byte length, which would break a byte-substring
// search and could violate necessity.
func literalFromRunes(runes []rune, flags syntax.Flags) (lit string, fold bool, ok bool) {
	foldRequested := flags&syntax.FoldCase != 0
	var b strings.Builder
	b.Grow(len(runes))
	for _, r := range runes {
		if foldRequested && isASCIILetter(r) {
			fold = true
		}
		if foldRequested && r > 127 {
			// Non-ASCII rune under (?i): bail. Even if this particular rune has
			// no fold, a mixed literal could still be unsafe to ASCII-fold, so
			// be conservative.
			return "", false, false
		}
		b.WriteRune(r)
	}
	return b.String(), fold, true
}

func isASCIILetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// MightMatch reports whether s might be matched by the source regex. It is a
// necessary condition for a match (never a false negative). It allocates
// nothing and is safe for concurrent use.
func (p *Prefilter) MightMatch(s string) bool {
	if p == nil {
		// No prefilter => cannot screen; defer to the regex (caller handles).
		return true
	}
	if !p.foldCase {
		if len(p.needles) == 1 {
			return strings.Contains(s, p.needles[0])
		}
		for _, n := range p.needles {
			if strings.Contains(s, n) {
				return true
			}
		}
		return false
	}
	// Case-folded path: needles are pre-lowercased. Compare against s with an
	// on-the-fly ASCII lowering of s, without allocating a lowered copy.
	for _, n := range p.needles {
		if containsFoldASCII(s, n) {
			return true
		}
	}
	return false
}

// containsFoldASCII reports whether s contains needle, comparing ASCII letters
// case-insensitively. needle must already be ASCII-lowercased. It allocates
// nothing. needle is assumed non-empty (Build never keeps empty needles).
func containsFoldASCII(s, needle string) bool {
	n := len(needle)
	if n == 0 {
		return true
	}
	if len(s) < n {
		return false
	}
	last := len(s) - n
	c0 := needle[0]
	for i := 0; i <= last; i++ {
		if lowerASCII(s[i]) != c0 {
			continue
		}
		j := 1
		for ; j < n; j++ {
			if lowerASCII(s[i+j]) != needle[j] {
				break
			}
		}
		if j == n {
			return true
		}
	}
	return false
}

// lowerASCII lowercases a single byte if it is an ASCII uppercase letter.
func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
