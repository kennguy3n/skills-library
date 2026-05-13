// skills-mcp serves the Skills Library over the Model Context Protocol.
//
// Transport: JSON-RPC 2.0 over stdio. One JSON-RPC message per line.
//
// Supported methods:
//
//	initialize          — protocol handshake
//	tools/list          — enumerate the 4 tools below
//	tools/call          — invoke one of the tools
//
// Tools exposed:
//
//	lookup_vulnerability(package, ecosystem, version?)
//	check_secret_pattern(text)
//	get_skill(skill_id, budget?)
//	search_skills(query)
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

	"github.com/kennguy3n/skills-library/cmd/skills-mcp/internal/mcp"
)

func main() {
	libraryPath := flag.String("path", "", "path to the skills-library checkout (default: $SKILLS_LIBRARY_PATH or dir of the binary)")
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
