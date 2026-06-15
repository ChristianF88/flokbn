package cli

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	cli "github.com/urfave/cli/v2"
)

// exampleAssets holds the committed scaffold inputs unpacked by
// `flokbn example config`: the runnable complex static-analysis config plus
// the four IP/UA list files it references.
//
//go:embed exampledata
var exampleAssets embed.FS

const exampleConfigName = "complex-static.toml"

// scaffoldLists are the list files copied verbatim into the scaffold directory.
var scaffoldLists = []string{
	"whitelist.txt",
	"blacklist.txt",
	"ua_whitelist.txt",
	"ua_blacklist.txt",
}

// scaffoldPaths maps each path key in the embedded config to the co-located
// file name it must point at after scaffolding. `example config` rewrites each
// key's value to an absolute path inside the output directory so the config is
// runnable from any working directory.
var scaffoldPaths = []struct{ key, file string }{
	{"jailFile", "flokbn_jail.json"},
	{"banFile", "flokbn_ban.txt"},
	{"whitelist", "whitelist.txt"},
	{"blacklist", "blacklist.txt"},
	{"userAgentWhitelist", "ua_whitelist.txt"},
	{"userAgentBlacklist", "ua_blacklist.txt"},
	{"logFile", "access.log"},
	{"plotPath", "heatmap.html"},
}

var exampleCommand = &cli.Command{
	Name:  "example",
	Usage: "Generate example inputs (synthetic logs and a runnable config scaffold)",
	Subcommands: []*cli.Command{
		{
			Name:  "logs",
			Usage: "Generate a synthetic access log matching the complex example",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "out",
					Usage:    "Output log file path (required)",
					Required: true,
				},
				&cli.Int64Flag{
					Name:  "lines",
					Usage: "Number of log lines to generate",
					Value: synthDefaultLines,
				},
				&cli.Uint64Flag{
					Name:  "seed",
					Usage: "PRNG seed (same seed => identical output)",
					Value: synthDefaultSeed,
				},
			},
			Action: handleExampleLogs,
		},
		{
			Name:  "config",
			Usage: "Scaffold a runnable complex static-analysis config into a directory",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "out",
					Usage:    "Output directory for the scaffolded config and list files (required)",
					Required: true,
				},
			},
			Action: handleExampleConfig,
		},
	},
}

// handleExampleLogs generates a synthetic access log to the --out file.
func handleExampleLogs(c *cli.Context) error {
	out := c.String("out")
	lines := c.Int64("lines")
	seed := c.Uint64("seed")

	if lines <= 0 {
		return fmt.Errorf("example logs: --lines must be positive, got %d", lines)
	}

	f, err := os.Create(out)
	if err != nil {
		return fmt.Errorf("example logs: %w", err)
	}
	if err := generateSyntheticLog(f, lines, seed); err != nil {
		f.Close()
		os.Remove(out) // don't leave a truncated log behind
		return fmt.Errorf("example logs: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("example logs: %w", err)
	}
	fmt.Fprintf(c.App.Writer, "example logs: wrote %d lines to %s (seed %d)\n", lines, out, seed)
	return nil
}

// handleExampleConfig scaffolds the complex example into the --out directory:
// it writes the four list files verbatim and the config with every path key
// rewritten to an absolute path inside the directory, so the scaffold runs
// as-is from any working directory.
func handleExampleConfig(c *cli.Context) error {
	out := c.String("out")
	absDir, err := filepath.Abs(out)
	if err != nil {
		return fmt.Errorf("example config: %w", err)
	}
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		return fmt.Errorf("example config: %w", err)
	}

	// List files: copied verbatim.
	for _, name := range scaffoldLists {
		data, err := exampleAssets.ReadFile("exampledata/" + name)
		if err != nil {
			return fmt.Errorf("example config: %w", err)
		}
		if err := os.WriteFile(filepath.Join(absDir, name), data, 0o644); err != nil {
			return fmt.Errorf("example config: %w", err)
		}
	}

	// Config: rewrite path keys to absolute, co-located targets.
	raw, err := exampleAssets.ReadFile("exampledata/" + exampleConfigName)
	if err != nil {
		return fmt.Errorf("example config: %w", err)
	}
	rewritten := rewriteScaffoldPaths(string(raw), absDir)
	if err := os.WriteFile(filepath.Join(absDir, exampleConfigName), []byte(rewritten), 0o644); err != nil {
		return fmt.Errorf("example config: %w", err)
	}

	cfgPath := filepath.Join(absDir, exampleConfigName)
	logPath := filepath.Join(absDir, "access.log")
	w := c.App.Writer
	fmt.Fprintf(w, "example config: scaffolded into %s\n", absDir)
	fmt.Fprintln(w, "Next steps:")
	fmt.Fprintf(w, "  flokbn example logs   --out %s --lines 10000000\n", logPath)
	fmt.Fprintf(w, "  flokbn static --config %s --plain\n", cfgPath)
	return nil
}

// rewriteScaffoldPaths rewrites the value of each known path key in the
// embedded TOML to an absolute path inside absDir, using forward slashes so
// the result is a valid TOML basic string on every platform (os.Open accepts
// forward slashes on Windows). Keys are matched line-anchored, so
// "userAgentWhitelist" never matches the "whitelist" rule.
func rewriteScaffoldPaths(toml, absDir string) string {
	for _, p := range scaffoldPaths {
		target := filepath.ToSlash(filepath.Join(absDir, p.file))
		// Escape for a TOML basic string first (backslash before quote so the
		// quote's escape backslash is not doubled), then escape '$' so it is
		// not read as a capture-group reference in the replacement template.
		safe := strings.ReplaceAll(target, `\`, `\\`)
		safe = strings.ReplaceAll(safe, `"`, `\"`)
		safe = strings.ReplaceAll(safe, `$`, `$$`)
		re := regexp.MustCompile(`(?m)^(\s*` + regexp.QuoteMeta(p.key) + `\s*=\s*)"[^"]*"(.*)$`)
		toml = re.ReplaceAllString(toml, `${1}"`+safe+`"${2}`)
	}
	return toml
}
