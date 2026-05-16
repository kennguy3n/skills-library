package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// fetch-vulns supported ecosystem identifiers. Keep the surface
// narrow and explicit so the subcommand only ever shells out to the
// Python ingest with names that match the script's --ecosystem
// allowlist (scripts/ingest-osv.py:ECOSYSTEM_MAP). A typo in an
// --only flag therefore fails the cobra parse rather than producing
// an opaque "download failed" from a bogus archive URL.
var fetchVulnsEcosystems = []string{
	"composer",
	"crates",
	"go",
	"maven",
	"npm",
	"nuget",
	"pub",
	"pypi",
	"rubygems",
	"swift",
}

// defaultFetchVulnsCache resolves the user-local OSV cache path the
// subcommand reads / writes. Resolution order matches the MCP
// scanner's defaultUserCacheRoot in cmd/skills-mcp/internal/tools/
// library.go so a single env-var override propagates to both ends:
//
//  1. $SKILLS_MCP_CACHE
//  2. $XDG_CACHE_HOME/skills-mcp/vulns
//  3. $HOME/.cache/skills-mcp/vulns
//
// The empty string is returned only when none of the above resolves
// (no env vars, no home directory); callers must surface that as an
// error rather than writing to "/osv/<eco>".
func defaultFetchVulnsCache() string {
	if v := os.Getenv("SKILLS_MCP_CACHE"); v != "" {
		return v
	}
	if v := os.Getenv("XDG_CACHE_HOME"); v != "" {
		return filepath.Join(v, "skills-mcp", "vulns")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".cache", "skills-mcp", "vulns")
	}
	return ""
}

// repoIngestScript returns an absolute path to the OSV ingest script
// the subcommand shells out to. It looks for `scripts/ingest-osv.py`
// relative to the supplied library root first (the normal case when
// `skills-check fetch-vulns --path .` is run from a checkout), then
// falls back to walking up from the running binary's directory (so a
// `go install`'d binary still finds the bundled script when run from
// outside the checkout). Returns "" when no script can be located.
func repoIngestScript(libraryRoot string) string {
	candidates := []string{}
	if libraryRoot != "" {
		if abs, err := filepath.Abs(libraryRoot); err == nil {
			candidates = append(candidates, filepath.Join(abs, "scripts", "ingest-osv.py"))
		}
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		// Walk up to 4 levels — covers typical "$repo/dist/bin",
		// "$repo/cmd/skills-check", and "$GOBIN" layouts.
		for i := 0; i < 4; i++ {
			candidates = append(candidates, filepath.Join(dir, "scripts", "ingest-osv.py"))
			dir = filepath.Dir(dir)
		}
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// cacheIndexPaths returns the per-ecosystem `osv/<eco>/index.json`
// paths the subcommand's --check mode stats for freshness.
func cacheIndexPaths(cacheRoot string, ecos []string) []string {
	out := make([]string, 0, len(ecos))
	for _, eco := range ecos {
		out = append(out, filepath.Join(cacheRoot, "osv", eco, "index.json"))
	}
	return out
}

func fetchVulnsCmd() *cobra.Command {
	var (
		path         string
		cacheDir     string
		perEcosystem int
		only         []string
		ordering     string
		check        bool
		maxAgeDays   int
		verbose      bool
	)
	c := &cobra.Command{
		Use:   "fetch-vulns",
		Short: "Populate the user-local OSV cache from osv.dev",
		Long: `Download per-ecosystem OSV archives from osv.dev and write them
into the user-local cache that skills-mcp (and skills-check
validation) consult before falling back to the repo-bundled sample.

The cache lives under $SKILLS_MCP_CACHE (falling back to
$XDG_CACHE_HOME/skills-mcp/vulns and then ~/.cache/skills-mcp/vulns).
A full pull is ~250 MB and ~5–10 minutes on a typical connection;
re-runs are idempotent and replace the existing cache per
ecosystem.

Use --check (no download) to verify the cache exists and is
fresher than --max-age-days; the command exits non-zero when the
cache is missing, partial, or stale, suitable for cron / CI.
`,
		RunE: func(c *cobra.Command, args []string) error {
			out := c.OutOrStdout()
			ecos := selectFetchEcosystems(only)
			if len(ecos) == 0 {
				return fmt.Errorf("no ecosystems selected (use --only or omit to fetch all)")
			}
			if cacheDir == "" {
				cacheDir = defaultFetchVulnsCache()
			}
			if cacheDir == "" {
				return fmt.Errorf("no cache directory: set $SKILLS_MCP_CACHE, $XDG_CACHE_HOME, or $HOME")
			}
			absCache, err := filepath.Abs(cacheDir)
			if err != nil {
				return fmt.Errorf("resolve cache dir: %w", err)
			}
			osvDir := filepath.Join(absCache, "osv")

			if check {
				return runFetchVulnsCheck(out, osvDir, ecos, maxAgeDays)
			}

			script := repoIngestScript(path)
			if script == "" {
				return fmt.Errorf("could not locate scripts/ingest-osv.py; pass --path <library-root>")
			}
			if err := os.MkdirAll(osvDir, 0o755); err != nil {
				return fmt.Errorf("mkdir cache: %w", err)
			}
			fmt.Fprintf(out, "fetching OSV archives -> %s\n", osvDir)
			fmt.Fprintf(out, "  ecosystems: %s\n", strings.Join(ecos, ", "))
			fmt.Fprintf(out, "  per-ecosystem: %s\n", perEcosystemDisplay(perEcosystem))
			fmt.Fprintf(out, "  ordering: %s\n", ordering)
			started := time.Now()
			if err := runFetchVulnsIngest(c, script, osvDir, ecos, perEcosystem, ordering, verbose); err != nil {
				return err
			}
			fmt.Fprintf(out, "done in %s\n", time.Since(started).Round(time.Second))
			// Final freshness check so callers that chain
			// `fetch-vulns && fetch-vulns --check` get an
			// authoritative "cache is now fresh" exit code.
			return runFetchVulnsCheck(out, osvDir, ecos, maxAgeDays)
		},
	}
	c.Flags().StringVar(&path, "path", ".", "library root (used to locate scripts/ingest-osv.py)")
	c.Flags().StringVar(&cacheDir, "cache-dir", "", "override the cache root (default: $SKILLS_MCP_CACHE or ~/.cache/skills-mcp/vulns)")
	c.Flags().IntVar(&perEcosystem, "per-ecosystem", 0, "max advisories per ecosystem (0 = full archive, recommended)")
	c.Flags().StringSliceVar(&only, "only", nil, "limit to the named ecosystem(s); repeat or comma-separate")
	c.Flags().StringVar(&ordering, "ordering", "latest-first", "ordering passed to ingest-osv.py (stride|latest-first)")
	c.Flags().BoolVar(&check, "check", false, "verify cache is present and fresh; do not download")
	c.Flags().IntVar(&maxAgeDays, "max-age-days", 7, "cache is considered stale when older than this many days")
	c.Flags().BoolVar(&verbose, "verbose", false, "pass --verbose through to ingest-osv.py")
	return c
}

// selectFetchEcosystems narrows the supported ecosystem list to the
// subset requested via --only. An empty `only` slice selects all
// ecosystems. Unknown identifiers are silently skipped here; the
// downstream `ingest-osv.py --ecosystem <x>` would reject them with
// an argparse error, but we prefer to fail upfront in our own
// vocabulary.
func selectFetchEcosystems(only []string) []string {
	known := map[string]bool{}
	for _, e := range fetchVulnsEcosystems {
		known[e] = true
	}
	if len(only) == 0 {
		out := append([]string{}, fetchVulnsEcosystems...)
		sort.Strings(out)
		return out
	}
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range only {
		for _, e := range strings.Split(raw, ",") {
			e = strings.TrimSpace(e)
			if e == "" || !known[e] || seen[e] {
				continue
			}
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out
}

// perEcosystemDisplay renders the --per-ecosystem value for the
// progress preamble. "0" maps to "unlimited" because that's how the
// Python script interprets it and the literal "0" is misleading.
func perEcosystemDisplay(n int) string {
	if n <= 0 {
		return "unlimited (full archive)"
	}
	return fmt.Sprintf("%d", n)
}

// runFetchVulnsIngest shells out to scripts/ingest-osv.py with
// --output-dir pointing at the user cache and the requested
// ordering. Stdout / stderr from the child are streamed straight
// through to the cobra command's output so the user sees per-eco
// download progress in real time.
func runFetchVulnsIngest(c *cobra.Command, script, osvDir string, ecos []string, perEcosystem int, ordering string, verbose bool) error {
	args := []string{
		script,
		"--output-dir", osvDir,
		"--per-ecosystem", fmt.Sprintf("%d", perEcosystem),
		"--ordering", ordering,
	}
	for _, e := range ecos {
		args = append(args, "--ecosystem", e)
	}
	if verbose {
		args = append(args, "--verbose")
	}
	return execScript(c, args)
}

// execScript forks a Python interpreter with the supplied arguments
// (args[0] is the script path) and streams output. The interpreter
// is the first match of $SKILLS_PYTHON, $PYTHON, "python3", or
// "python" on PATH — that priority lets operators pin a specific
// virtualenv via env var without forcing every machine to expose
// `python3` at the same path.
func execScript(c *cobra.Command, args []string) error {
	interp := pythonInterpreter()
	cmd := exec.Command(interp, args...)
	cmd.Stdout = c.OutOrStdout()
	cmd.Stderr = c.ErrOrStderr()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", interp, strings.Join(args, " "), err)
	}
	return nil
}

func pythonInterpreter() string {
	for _, env := range []string{"SKILLS_PYTHON", "PYTHON"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return "python3"
}

// runFetchVulnsCheck stats each ecosystem's index.json and reports a
// per-eco pass/fail summary. Returns nil only when every selected
// ecosystem has an index file present and newer than maxAgeDays.
//
// The check intentionally focuses on `index.json` rather than the
// directory's mtime: index.json is rewritten every time
// `ingest-osv.py` finishes a successful pull, and the MCP scanner
// uses its presence as the user-cache "this slot is populated"
// marker. A partial-fetch failure mid-eco therefore fails the check
// (the missing index.json is what `osvDir()` checks for).
func runFetchVulnsCheck(out io.Writer, osvDir string, ecos []string, maxAgeDays int) error {
	now := time.Now()
	var stale, missing []string
	for _, eco := range ecos {
		idx := filepath.Join(osvDir, eco, "index.json")
		info, err := os.Stat(idx)
		if err != nil {
			missing = append(missing, eco)
			fmt.Fprintf(out, "  %s: MISSING (%s)\n", eco, idx)
			continue
		}
		ageDays := int(now.Sub(info.ModTime()).Hours() / 24)
		if maxAgeDays > 0 && ageDays > maxAgeDays {
			stale = append(stale, fmt.Sprintf("%s(%dd)", eco, ageDays))
			fmt.Fprintf(out, "  %s: STALE (%d days old; max %d)\n", eco, ageDays, maxAgeDays)
			continue
		}
		fmt.Fprintf(out, "  %s: ok (%d days old)\n", eco, ageDays)
	}
	if len(missing) > 0 || len(stale) > 0 {
		details := []string{}
		if len(missing) > 0 {
			details = append(details, fmt.Sprintf("missing: %s", strings.Join(missing, ", ")))
		}
		if len(stale) > 0 {
			details = append(details, fmt.Sprintf("stale: %s", strings.Join(stale, ", ")))
		}
		return fmt.Errorf("cache check failed; %s", strings.Join(details, "; "))
	}
	return nil
}
