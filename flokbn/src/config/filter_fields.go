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

// validateLiveFilterFields is validateFilterFields for live mode: every
// [live.<name>] window filter and the [global] User-Agent lists against the
// effective [live] logFormat. It also requires the timestamp itself: a
// sliding window is bounded in time, and a request without a timestamp never
// enters one.
func (c *Config) validateLiveFilterFields(diags *ConfigDiagnostics, effFormat string) {
	fields := scanLogFormatFields(effFormat)
	if !fields.timestamp {
		diags.AddRaw(fmt.Sprintf("[live] logFormat %s has no %%t field; live mode needs the timestamp of each request for its sliding windows - add %%t to logFormat",
			quoteCapped(effFormat)))
	}
	if fields.userAgent && fields.uri {
		return
	}
	missing := missingFieldReporter(diags, "[live] logFormat", effFormat)

	for name, stc := range c.LiveTries {
		if stc == nil {
			continue
		}
		section := "live." + name
		if !fields.userAgent && stc.UserAgentRegex != "" {
			missing(section, "useragentRegex", "User-Agent", "%u")
		}
		if !fields.uri && stc.EndpointRegex != "" {
			missing(section, "endpointRegex", "request URI", "%r or %U")
		}
	}
	c.validateGlobalFilterFields(fields, missing)
}

// validateFilterFields cross-checks every static filter against the fields the
// effective [static] logFormat extracts and records one diagnostic per filter
// whose field is missing (collect-all). Live mode has its own logFormat and
// its own check, validateLiveFilterFields.
func (c *Config) validateFilterFields(diags *ConfigDiagnostics, effFormat string) {
	fields := scanLogFormatFields(effFormat)
	if fields.userAgent && fields.uri && fields.timestamp {
		return
	}
	missing := missingFieldReporter(diags, "logFormat", effFormat)

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

	c.validateGlobalFilterFields(fields, missing)
}
