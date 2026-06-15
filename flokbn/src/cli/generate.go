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

// demoAssets holds the committed inputs unpacked by `flokbn generate
// static-demo`: the complex static-analysis config plus the four IP/UA list
// files it references.
//
//go:embed exampledata
var demoAssets embed.FS

const demoConfigName = "complex-static.toml"

// demoLines is the fixed size of the synthetic log `generate static-demo`
// writes. The embedded config's clusterArgSets minimum sizes are calibrated for
// exactly this many lines, so the generated log and config always match.
const demoLines = synthDefaultLines

// demoLists are the list files copied verbatim into the demo directory.
var demoLists = []string{
	"whitelist.txt",
	"blacklist.txt",
	"ua_whitelist.txt",
	"ua_blacklist.txt",
}

// demoPaths maps each path key in the embedded config to the co-located file
// name it must point at. `generate static-demo` rewrites each key's value to an
// absolute path inside the output directory so the config is runnable from any
// working directory.
var demoPaths = []struct{ key, file string }{
	{"jailFile", "flokbn_jail.json"},
	{"banFile", "flokbn_ban.txt"},
	{"whitelist", "whitelist.txt"},
	{"blacklist", "blacklist.txt"},
	{"userAgentWhitelist", "ua_whitelist.txt"},
	{"userAgentBlacklist", "ua_blacklist.txt"},
	{"logFile", "access.log"},
	{"plotPath", "heatmap.html"},
}

var generateCommand = &cli.Command{
	Name:  "generate",
	Usage: "Generate ready-to-run example inputs",
	Subcommands: []*cli.Command{
		{
			Name:  "static-demo",
			Usage: "Generate a self-contained static-analysis demo: a synthetic log, a matching config, and its list files",
			Description: "Writes a complete, runnable static-analysis example into the directory\n" +
				"given by --out (a folder, defaulting to the current directory): a fixed\n" +
				"1,000,000-line synthetic access log, the four IP/User-Agent list files, and\n" +
				"a config whose cluster thresholds are calibrated to that log. Every path in\n" +
				"the config is absolute and co-located, so it runs from any working directory:\n\n" +
				"   flokbn generate static-demo --out ./demo   # or just: flokbn generate static-demo\n" +
				"   flokbn static --config ./demo/complex-static.toml --plain",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "out",
					Usage: "`directory` to create the demo in (defaults to the current directory). Receives the generated access.log, the calibrated config, and the IP/UA list files.",
					Value: ".",
				},
			},
			Action: handleStaticDemo,
		},
	},
}

// handleStaticDemo writes the complete static-analysis demo into --out: the
// list files verbatim, the config with every path rewritten to an absolute
// co-located target, and a fixed 1,000,000-line synthetic access log the
// embedded config is calibrated for. The result runs as-is from any directory.
func handleStaticDemo(c *cli.Context) error {
	// Reject stray positional arguments. Without this, a misplaced flag such as
	// `static-demo --out ./demo extra` is silently swallowed as positional args
	// instead of surfacing the mistake to the user.
	if c.Args().Len() > 0 {
		return fmt.Errorf("generate static-demo: unexpected argument(s) %v; "+
			"usage: flokbn generate static-demo --out <dir>", c.Args().Slice())
	}
	absDir, err := filepath.Abs(c.String("out"))
	if err != nil {
		return fmt.Errorf("generate static-demo: %w", err)
	}

	// Track what we create so a failure partway through cleans up only the
	// artifacts WE wrote — never pre-existing user data. MkdirAll(absDir) may
	// create not just the leaf but every missing ancestor (e.g. --out a/b/new
	// creates a, a/b and a/b/new), so walk upward from absDir to the first
	// existing ancestor and record the directories that do not yet exist. On
	// failure we remove exactly those, deepest-first, so no empty intermediate
	// directory we created is leaked.
	createdDirs := dirsToCreate(absDir)
	var created []string
	success := false
	defer func() {
		if success {
			return
		}
		for i := len(created) - 1; i >= 0; i-- {
			_ = os.Remove(created[i])
		}
		// Remove the directories WE created, deepest-first. Remove (not
		// RemoveAll) fails harmlessly if a directory is non-empty, so any
		// unexpected pre-existing content keeps it from being deleted.
		for _, dir := range createdDirs {
			_ = os.Remove(dir)
		}
	}()

	if err := os.MkdirAll(absDir, 0o755); err != nil {
		return fmt.Errorf("generate static-demo: %w", err)
	}

	// List files: copied verbatim.
	for _, name := range demoLists {
		data, err := demoAssets.ReadFile("exampledata/" + name)
		if err != nil {
			return fmt.Errorf("generate static-demo: %w", err)
		}
		listPath := filepath.Join(absDir, name)
		if err := os.WriteFile(listPath, data, 0o644); err != nil {
			return fmt.Errorf("generate static-demo: %w", err)
		}
		created = append(created, listPath)
	}

	// Config: the embedded cluster thresholds are already calibrated for the
	// fixed demoLines log, so only the path keys are rewritten to absolute,
	// co-located targets.
	raw, err := demoAssets.ReadFile("exampledata/" + demoConfigName)
	if err != nil {
		return fmt.Errorf("generate static-demo: %w", err)
	}
	cfg := rewriteScaffoldPaths(string(raw), absDir)
	cfgPath := filepath.Join(absDir, demoConfigName)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return fmt.Errorf("generate static-demo: %w", err)
	}
	created = append(created, cfgPath)

	// Synthetic access log.
	logPath := filepath.Join(absDir, "access.log")
	f, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("generate static-demo: %w", err)
	}
	if err := generateSyntheticLog(f, demoLines, synthDefaultSeed); err != nil {
		f.Close()
		// Close the file, then track the truncated log so the deferred cleanup
		// removes it (and everything else we wrote) on the way out.
		created = append(created, logPath)
		return fmt.Errorf("generate static-demo: %w", err)
	}
	if err := f.Close(); err != nil {
		// The on-disk file may be incomplete; track it for deferred cleanup.
		created = append(created, logPath)
		return fmt.Errorf("generate static-demo: %w", err)
	}
	created = append(created, logPath)

	w := c.App.Writer
	fmt.Fprintf(w, "generate static-demo: wrote a 1,000,000-line demo into %s\n", absDir)
	fmt.Fprintln(w, "Run it with:")
	fmt.Fprintf(w, "  flokbn static --config %s --plain\n", cfgPath)
	success = true
	return nil
}

// dirsToCreate returns the directories that os.MkdirAll(absDir) would create,
// ordered deepest-first (leaf before its parents). It walks upward from absDir
// to the first existing ancestor: every directory above that point already
// exists and is left out. The deepest-first order lets a failure-cleanup loop
// os.Remove each one in turn — a leaf is always emptied before its parent is
// reached, so empty directories we created unwind cleanly while a parent that
// still holds unrelated content is left intact. If absDir already exists the
// result is empty (we create nothing). absDir must be absolute.
func dirsToCreate(absDir string) []string {
	var dirs []string
	for dir := filepath.Clean(absDir); ; {
		if _, err := os.Stat(dir); err == nil {
			break // first existing ancestor: stop, it is not ours to remove
		}
		dirs = append(dirs, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached the filesystem root
		}
		dir = parent
	}
	return dirs
}

// rewriteScaffoldPaths rewrites the value of each known path key in the
// embedded TOML to an absolute path inside absDir, using forward slashes so
// the result is a valid TOML basic string on every platform (os.Open accepts
// forward slashes on Windows). Keys are matched line-anchored, so
// "userAgentWhitelist" never matches the "whitelist" rule.
func rewriteScaffoldPaths(toml, absDir string) string {
	for _, p := range demoPaths {
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
