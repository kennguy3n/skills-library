package cmd

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/kennguy3n/skills-library/cmd/skills-check/internal/compiler"
	"github.com/kennguy3n/skills-library/internal/skill"
)

func regenerateCmd() *cobra.Command {
	var path, tool, budget, profileName string
	var fullInline, legacy bool
	c := &cobra.Command{
		Use:   "regenerate",
		Short: "Rebuild dist/ files from the current skills/",
		RunE: func(c *cobra.Command, args []string) error {
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			skills, err := skill.LoadAll(filepath.Join(abs, "skills"))
			if err != nil {
				return err
			}
			if profileName != "" {
				prof, err := compiler.LoadProfile(abs, profileName)
				if err != nil {
					return err
				}
				skills = compiler.FilterSkillsByProfile(skills, prof)
				if len(skills) == 0 {
					return fmt.Errorf("profile %q matched no skills", profileName)
				}
			}
			ctx, err := compiler.LoadContext(abs)
			if err != nil {
				return err
			}
			// --full-inline (alias --legacy) restores the pre-v2
			// monolithic AGENTS.md output. The default since v2 is
			// the minimal pointer file documented in agents.go.
			if fullInline || legacy {
				ctx.AgentsFullInline = true
			}
			outDir := filepath.Join(abs, "dist")

			var formatters []compiler.Formatter
			if tool == "" || tool == "all" {
				formatters = compiler.AllTools()
			} else {
				f, ok := compiler.Registry[tool]
				if !ok {
					return fmt.Errorf("unknown tool %q", tool)
				}
				formatters = []compiler.Formatter{f}
			}

			out := c.OutOrStdout()
			var warnings []string
			for _, f := range formatters {
				tier := f.DefaultTier()
				if budget != "" {
					if !skill.IsValidTier(budget) {
						return fmt.Errorf("invalid budget %q (valid: minimal, compact, full)", budget)
					}
					tier = skill.Tier(budget)
				}
				report, warns, err := compiler.WriteFile(skills, f.Name(), tier, ctx, outDir)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "%-10s -> dist/%s  total=%d openai / %d claude tokens (%s tier)\n",
					f.Name(), f.OutputName(), report.Total.OpenAI, report.Total.Claude, tier)
				warnings = append(warnings, warns...)
			}
			sort.Strings(warnings)
			for _, w := range warnings {
				fmt.Fprintln(c.ErrOrStderr(), "warn:", w)
			}
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", ".", "library root")
	c.Flags().StringVar(&tool, "tool", "", "single tool to regenerate (default all)")
	c.Flags().StringVar(&budget, "budget", "", "override tier (minimal|compact|full)")
	c.Flags().StringVar(&profileName, "profile", "", "enterprise profile (e.g., financial-services|healthcare|government)")
	c.Flags().BoolVar(&fullInline, "full-inline", false, "render the legacy AGENTS.md output that inlines every skill body (default is the minimal pointer file)")
	c.Flags().BoolVar(&legacy, "legacy", false, "alias for --full-inline")
	return c
}
