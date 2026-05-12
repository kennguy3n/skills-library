package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kennguy3n/skills-library/cmd/skills-check/internal/compiler"
	"github.com/kennguy3n/skills-library/cmd/skills-check/internal/skill"
)

func initCmd() *cobra.Command {
	var libraryPath, tool, skillsList, budget, outDir string
	c := &cobra.Command{
		Use:   "init",
		Short: "Generate an IDE-specific config file in the current project",
		RunE: func(c *cobra.Command, args []string) error {
			if tool == "" {
				return fmt.Errorf("--tool is required")
			}
			f, ok := compiler.Registry[tool]
			if !ok {
				return fmt.Errorf("unknown tool %q", tool)
			}
			tier := f.DefaultTier()
			if budget != "" {
				if !skill.IsValidTier(budget) {
					return fmt.Errorf("invalid budget %q (valid: minimal, compact, full)", budget)
				}
				tier = skill.Tier(budget)
			}

			lib, err := filepath.Abs(libraryPath)
			if err != nil {
				return err
			}
			all, err := skill.LoadAll(filepath.Join(lib, "skills"))
			if err != nil {
				return err
			}
			if skillsList != "" {
				want := map[string]bool{}
				for _, s := range strings.Split(skillsList, ",") {
					want[strings.TrimSpace(s)] = true
				}
				filtered := all[:0]
				for _, s := range all {
					if want[s.Frontmatter.ID] {
						filtered = append(filtered, s)
					}
				}
				if len(filtered) == 0 {
					return fmt.Errorf("no skills matched %q", skillsList)
				}
				all = filtered
			}

			ctx, err := compiler.LoadContext(lib)
			if err != nil {
				return err
			}
			if outDir == "" {
				outDir, err = os.Getwd()
				if err != nil {
					return err
				}
			}
			report, warns, err := compiler.WriteFile(all, tool, tier, ctx, outDir)
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			fmt.Fprintf(out, "wrote %s (%s tier, %d skills, %d openai / %d claude tokens)\n",
				filepath.Join(outDir, f.OutputName()), tier, len(all), report.Total.OpenAI, report.Total.Claude)
			for _, w := range warns {
				fmt.Fprintln(c.ErrOrStderr(), "warn:", w)
			}
			return nil
		},
	}
	c.Flags().StringVar(&libraryPath, "library", ".", "path to the skills-library checkout")
	c.Flags().StringVar(&tool, "tool", "", "target tool (claude|cursor|copilot|codex|agents|windsurf|devin|cline|universal)")
	c.Flags().StringVar(&skillsList, "skills", "", "comma-separated skill IDs (default: all skills)")
	c.Flags().StringVar(&budget, "budget", "", "tier override (minimal|compact|full)")
	c.Flags().StringVar(&outDir, "out", "", "output directory (default: cwd)")
	return c
}
