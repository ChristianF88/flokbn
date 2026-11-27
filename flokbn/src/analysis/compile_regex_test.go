package analysis

import (
	"errors"

	"github.com/ChristianF88/flokbn/config"
)

// compileRegex compiles the filters of tc the way the CLI does
// (CompileRegexInto) and returns the diagnostics report as an error, nil when
// every pattern compiles.
func compileRegex(tc *config.TrieCommon) error {
	var diags config.ConfigDiagnostics
	tc.CompileRegexInto("test", &diags)
	if diags.HasErrors() {
		return errors.New(diags.Report())
	}
	return nil
}
