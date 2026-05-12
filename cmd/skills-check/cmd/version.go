package cmd

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/kennguy3n/skills-library/cmd/skills-check/internal/manifest"
)

func versionCmd() *cobra.Command {
	var path string
	c := &cobra.Command{
		Use:   "version",
		Short: "Print CLI, library, and Go version",
		RunE: func(c *cobra.Command, args []string) error {
			out := c.OutOrStdout()
			fmt.Fprintf(out, "skills-check %s\n", CLIVersion)
			libVersion := "unknown"
			pubKey := "unset"
			if m, err := manifest.Load(filepath.Join(path, "manifest.json")); err == nil {
				libVersion = m.Version
				if m.PublicKeyID != "" {
					pubKey = m.PublicKeyID
				}
			}
			fmt.Fprintf(out, "library    %s\n", libVersion)
			fmt.Fprintf(out, "publickey  %s\n", pubKey)
			fmt.Fprintf(out, "go         %s\n", runtime.Version())
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", ".", "library root containing manifest.json")
	return c
}
