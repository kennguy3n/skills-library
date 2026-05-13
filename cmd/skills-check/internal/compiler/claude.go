package compiler

import (
	"strings"

	"github.com/kennguy3n/skills-library/internal/skill"
)

type claudeFormatter struct{}

func (claudeFormatter) Name() string            { return "claude" }
func (claudeFormatter) OutputName() string      { return "CLAUDE.md" }
func (claudeFormatter) DefaultTier() skill.Tier { return skill.TierCompact }

func (claudeFormatter) Format(skills []*skill.Skill, tier skill.Tier, ctx Context) string {
	var b strings.Builder
	b.WriteString(Header("Claude Code", tier, len(skills)))
	b.WriteString("Apply every skill below whenever you generate, review, or refactor code in this project. The rules are non-negotiable.\n\n")
	for _, s := range skills {
		b.WriteString(s.ExtractWithHeading(tier))
		b.WriteString("\n")
	}
	b.WriteString(VulnSummary(ctx))
	b.WriteString(GlossaryBlock(ctx))
	b.WriteString(AttackBlock(ctx))
	return b.String()
}
