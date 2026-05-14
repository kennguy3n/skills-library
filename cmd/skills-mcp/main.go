// skills-mcp serves the Skills Library over the Model Context Protocol.
//
// Transport: JSON-RPC 2.0 over stdio. One JSON-RPC message per line.
//
// Supported methods:
//
//	initialize          — protocol handshake
//	tools/list          — enumerate the 10 tools below
//	tools/call          — invoke one of the tools
//
// Tools exposed:
//
//	lookup_vulnerability(package, ecosystem?, version?)
//	check_secret_pattern(text)
//	get_skill(skill_id, budget?)
//	search_skills(query)
//	scan_secrets(text | file_path, format?)
//	check_dependency(package, version, ecosystem, format?)
//	check_typosquat(package, ecosystem?)
//	map_compliance_control(skill_id | query, framework?)
//	get_sigma_rule(rule_id | query, category?)
//	version_status()
//
// The library root is determined by, in order:
//   - --path <dir>
//   - $SKILLS_LIBRARY_PATH
//   - the directory containing the running binary
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kennguy3n/skills-library/cmd/skills-mcp/internal/mcp"
)

func main() {
	libraryPath := flag.String("path", "", "path to the skills-library checkout (default: $SKILLS_LIBRARY_PATH or dir of the binary)")
	allowedRoots := flag.String("allowed-roots", "", "comma-separated absolute directories that scan_secrets is permitted to read from. When unset, ScanSecrets accepts any path the process can stat (sensitive system directories such as ~/.ssh, ~/.aws, ~/.gnupg and /etc/shadow are always denied regardless).")
	flag.Parse()

	root, err := resolveLibraryRoot(*libraryPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	srv, err := mcp.NewServer(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if *allowedRoots != "" {
		roots := strings.Split(*allowedRoots, ",")
		if err := srv.SetAllowedRoots(roots); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}
	if err := srv.Serve(bufio.NewReader(os.Stdin), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func resolveLibraryRoot(arg string) (string, error) {
	if arg != "" {
		return filepath.Abs(arg)
	}
	if env := os.Getenv("SKILLS_LIBRARY_PATH"); env != "" {
		return filepath.Abs(env)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve binary path: %w", err)
	}
	return filepath.Dir(exe), nil
}
