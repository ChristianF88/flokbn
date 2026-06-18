package cli

import (
	"fmt"
	"os"

	"github.com/ChristianF88/flokbn/config"
	cli "github.com/urfave/cli/v2"
)

// barrier is the pre-work gate for config diagnostics. When d has errors it
// writes the enumerated, sorted report to stderr itself and returns
// cli.Exit("", 1).
//
// The empty cli.Exit message is deliberate: urfave/cli's HandleExitCoder prints
// nothing for an empty message and calls os.Exit(1) inside App.Run, so this
// report is the only write to stderr (no duplicate "flokbn:" prefix line from
// main.go, which is never reached). The barrier runs before anything
// side-effecting, so the deferred cleanup that os.Exit skips has nothing to do.
func barrier(d *config.ConfigDiagnostics) error {
	if d.HasErrors() {
		fmt.Fprint(os.Stderr, d.Report())
		return cli.Exit("", 1)
	}
	return nil
}
