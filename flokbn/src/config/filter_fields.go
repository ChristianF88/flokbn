package config

import "fmt"

// logFormatFields records which optional request fields a logFormat extracts.
// A filter that reads a field the format never fills sees the zero value for
// every request: a regex or User-Agent list then matches nothing, a startTime
// excludes everything and an endTime excludes nothing - silently.
type logFormatFields struct {
	userAgent bool // %u
	uri       bool // %r (request line) or %U (standalone URI)
	timestamp bool // %t
}

// scanLogFormatFields walks a format string the same way the logparser format
// compiler does (a '%' consumes the following code byte) and notes the fields
// the filters depend on. It assumes the format already passed
// logparser.ValidateFormat.
func scanLogFormatFields(format string) logFormatFields {
	var f logFormatFields
	for i := 0; i+1 < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		switch format[i+1] {
		case 'u':
			f.userAgent = true
		case 'r', 'U':
			f.uri = true
		case 't':
			f.timestamp = true
		}
		i++ // skip the code byte
	}
	return f
}

// missingFieldReporter returns the function that records "filter key needs a
// field the logFormat lacks" for one mode. formatKey names the logFormat that
// is meant ("[static] logFormat" or "[live] logFormat"): the two modes have
// separate formats with different defaults.
func missingFieldReporter(diags *ConfigDiagnostics, formatKey, effFormat string) func(section, key, what, codes string) {
	qFormat := quoteCapped(effFormat)
	return func(section, key, what, codes string) {
		diags.AddRaw(fmt.Sprintf("[%s] %s needs the %s of each request, but %s %s has no %s field; add %s to logFormat or remove %s",
			section, key, what, formatKey, qFormat, codes, codes, key))
	}
}

// validateGlobalFilterFields checks the [global] User-Agent lists, which both
// modes apply to every request, against the fields of the mode's logFormat.
func (c *Config) validateGlobalFilterFields(fields logFormatFields, missing func(section, key, what, codes string)) {
	if fields.userAgent || c.Global == nil {
		return
	}
	if c.Global.UserAgentWhitelist != "" {
		missing("global", "userAgentWhitelist", "User-Agent", "%u")
	}
	if c.Global.UserAgentBlacklist != "" {
		missing("global", "userAgentBlacklist", "User-Agent", "%u")
	}
}

// validateFilterFields cross-checks every filter of the mode's tables, and the
// [global] User-Agent lists, against the fields the mode's effective logFormat
// extracts. It records one diagnostic per filter whose field is missing
// (collect-all): tables first, [global] last.
//
// The modes differ in the timestamp. Live mode needs it for every request: a
// sliding window is bounded in time, and a request without a timestamp never
// enters one. Static mode needs it only for a trie with a startTime/endTime. A
// live window does not apply those bounds (Config.LiveWarnings), so they are
// not checked against the live format.
func (c *Config) validateFilterFields(diags *ConfigDiagnostics, mode RunMode, effFormat string) {
	fields := scanLogFormatFields(effFormat)
	formatKey := "logFormat"
	boundsNeedTimestamp := !fields.timestamp
	if mode == LiveMode {
		formatKey = "[live] logFormat"
		boundsNeedTimestamp = false
		if !fields.timestamp {
			diags.AddRaw(fmt.Sprintf("[live] logFormat %s has no %%t field; live mode needs the timestamp of each request for its sliding windows - add %%t to logFormat",
				quoteCapped(effFormat)))
		}
	}
	if fields.userAgent && fields.uri && !boundsNeedTimestamp {
		return
	}
	missing := missingFieldReporter(diags, formatKey, effFormat)

	c.eachTrie(mode, func(section string, t *TrieCommon) {
		if !fields.userAgent && t.UserAgentRegex != "" {
			missing(section, "useragentRegex", "User-Agent", "%u")
		}
		if !fields.uri && t.EndpointRegex != "" {
			missing(section, "endpointRegex", "request URI", "%r or %U")
		}
		if boundsNeedTimestamp {
			// A bound that failed to parse is already reported by
			// validateTimestamps; the raw carrier still marks it as set.
			if t.StartTime != nil || t.startTimeRaw != "" {
				missing(section, "startTime", "timestamp", "%t")
			}
			if t.EndTime != nil || t.endTimeRaw != "" {
				missing(section, "endTime", "timestamp", "%t")
			}
		}
	})

	c.validateGlobalFilterFields(fields, missing)
}
