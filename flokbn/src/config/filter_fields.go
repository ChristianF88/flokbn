package config

import "fmt"

// logFormatFields records which optional request fields a static logFormat
// extracts. A filter that reads a field the format never fills sees the zero
// value for every request: a regex or User-Agent list then matches nothing, a
// startTime excludes everything and an endTime excludes nothing - silently.
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

// validateFilterFields cross-checks every static filter against the fields the
// effective logFormat extracts and records one diagnostic per filter whose
// field is missing (collect-all). Static mode only: live mode does not use
// [static] logFormat.
func (c *Config) validateFilterFields(diags *ConfigDiagnostics, effFormat string) {
	fields := scanLogFormatFields(effFormat)
	if fields.userAgent && fields.uri && fields.timestamp {
		return
	}
	qFormat := quoteCapped(effFormat)
	missing := func(section, key, what, codes string) {
		diags.AddRaw(fmt.Sprintf("[%s] %s needs the %s of each request, but logFormat %s has no %s field; add %s to logFormat or remove %s",
			section, key, what, qFormat, codes, codes, key))
	}

	for name, tc := range c.StaticTries {
		if tc == nil {
			continue
		}
		section := "static." + name
		if !fields.userAgent && tc.UserAgentRegex != "" {
			missing(section, "useragentRegex", "User-Agent", "%u")
		}
		if !fields.uri && tc.EndpointRegex != "" {
			missing(section, "endpointRegex", "request URI", "%r or %U")
		}
		if !fields.timestamp {
			// A bound that failed to parse is already reported by
			// validateTrieTimestamps; the raw carrier still marks it as set.
			if tc.StartTime != nil || tc.startTimeRaw != "" {
				missing(section, "startTime", "timestamp", "%t")
			}
			if tc.EndTime != nil || tc.endTimeRaw != "" {
				missing(section, "endTime", "timestamp", "%t")
			}
		}
	}

	if !fields.userAgent && c.Global != nil {
		if c.Global.UserAgentWhitelist != "" {
			missing("global", "userAgentWhitelist", "User-Agent", "%u")
		}
		if c.Global.UserAgentBlacklist != "" {
			missing("global", "userAgentBlacklist", "User-Agent", "%u")
		}
	}
}
