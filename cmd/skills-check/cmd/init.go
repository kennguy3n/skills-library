package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kennguy3n/skills-library/cmd/skills-check/internal/compiler"
	"github.com/kennguy3n/skills-library/cmd/skills-check/internal/scheduler"
	"github.com/kennguy3n/skills-library/internal/skill"
)

func initCmd() *cobra.Command {
	var libraryPath, tool, skillsList, budget, outDir, profileName string
	var noPrompt bool
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
			if profileName != "" {
				prof, err := compiler.LoadProfile(lib, profileName)
				if err != nil {
					return err
				}
				all = filterSkillsByProfile(all, prof)
				if len(all) == 0 {
					return fmt.Errorf("profile %q matched no skills", profileName)
				}
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

			if !noPrompt {
				maybeOfferScheduler(c.InOrStdin(), out)
			}
			return nil
		},
	}
	c.Flags().StringVar(&libraryPath, "library", ".", "path to the skills-library checkout")
	c.Flags().StringVar(&tool, "tool", "", "target tool (claude|cursor|copilot|codex|agents|windsurf|devin|cline|universal)")
	c.Flags().StringVar(&skillsList, "skills", "", "comma-separated skill IDs (default: all skills)")
	c.Flags().StringVar(&budget, "budget", "", "tier override (minimal|compact|full)")
	c.Flags().StringVar(&outDir, "out", "", "output directory (default: cwd)")
	c.Flags().BoolVar(&noPrompt, "no-prompt", false, "skip the interactive prompt to set up scheduled updates")
	c.Flags().StringVar(&profileName, "profile", "", "enterprise profile (e.g., financial-services|healthcare|government) — restricts the skill set")
	return c
}

// filterSkillsByProfile selects only those skills whose ID appears in the
// profile's skill list. If the profile has no skill list, the input is
// returned unchanged.
func filterSkillsByProfile(all []*skill.Skill, prof *compiler.Profile) []*skill.Skill {
	if prof == nil || len(prof.Skills) == 0 {
		return all
	}
	allowed := make(map[string]bool, len(prof.Skills))
	for _, s := range prof.Skills {
		allowed[s] = true
	}
	out := all[:0]
	for _, s := range all {
		if allowed[s.Frontmatter.ID] {
			out = append(out, s)
		}
	}
	return out
}

// maybeOfferScheduler asks the operator whether to install the background
// scheduled-update task. It is a no-op when the scheduler is already
// installed, when stdin is not a TTY, or when the user answers anything
// other than "y" / "yes".
func maybeOfferScheduler(stdin io.Reader, out io.Writer) {
	status, err := scheduler.Status()
	if err == nil && status != "" {
		return
	}
	if !isTerminal(stdin) {
		return
	}
	fmt.Fprint(out, "Would you like to set up automatic background updates? [y/N] ")
	reader := bufio.NewReader(stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	if answer != "y" && answer != "yes" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(out, "could not resolve current binary: %v\n", err)
		return
	}
	if err := scheduler.Install(scheduler.Defaults(exe)); err != nil {
		fmt.Fprintf(out, "scheduler install failed: %v\n", err)
		return
	}
	fmt.Fprintln(out, "scheduled update installed; run `skills-check scheduler status` to inspect")
}

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
