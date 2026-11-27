package config

import (
	"errors"
	"fmt"
)

// Test helpers: error-returning views of the collect-all validation, for
// tests that assert one message.

// ValidateLive runs the live-mode required-field checks and returns the first
// message as an error (nil when there is none). validateLiveInto emits in a
// fixed order, so "first" is stable.
func (c *Config) ValidateLive() error {
	d := &ConfigDiagnostics{}
	c.validateLiveInto(d)
	if len(d.msgs) > 0 {
		return fmt.Errorf("%s", d.msgs[0])
	}
	return nil
}

// CompileRegex compiles the filters of t and returns the compile errors of
// both fields joined (nil when both compile).
func (t *TrieCommon) CompileRegex() error {
	return errors.Join(t.compileRegexFields())
}

// Len returns the number of recorded diagnostics.
func (d *ConfigDiagnostics) Len() int { return len(d.msgs) }
