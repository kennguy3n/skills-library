package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func updateCmd() *cobra.Command {
	var regenerate, checkOnly, rollback bool
	c := &cobra.Command{
		Use:   "update",
		Short: "(Phase 2) Pull latest signed skills and vulnerability data",
		RunE: func(c *cobra.Command, args []string) error {
			out := c.OutOrStdout()
			fmt.Fprintln(out, "skills-check update: remote update channel ships in Phase 2.")
			fmt.Fprintln(out, "  - Signed manifest fetch + Ed25519 verification")
			fmt.Fprintln(out, "  - Delta application for large vulnerability data")
			fmt.Fprintln(out, "  - Atomic writes + rollback support")
			fmt.Fprintln(out, "Track progress in PROGRESS.md.")
			_ = regenerate
			_ = checkOnly
			_ = rollback
			return nil
		},
	}
	c.Flags().BoolVar(&regenerate, "regenerate", false, "regenerate dist/ files after update (Phase 2)")
	c.Flags().BoolVar(&checkOnly, "check-only", false, "show available updates without applying (Phase 2)")
	c.Flags().BoolVar(&rollback, "rollback", false, "revert to previous version (Phase 2)")
	return c
}
