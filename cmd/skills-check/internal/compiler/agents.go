package compiler

import (
	"fmt"
	"strings"

	"github.com/kennguy3n/skills-library/cmd/skills-check/internal/skill"
)

type agentsFormatter struct{}

func (agentsFormatter) Name() string            { return "agents" }
func (agentsFormatter) OutputName() string      { return "AGENTS.md" }
func (agentsFormatter) DefaultTier() skill.Tier { return skill.TierCompact }

func (agentsFormatter) Format(skills []*skill.Skill, tier skill.Tier, ctx Context) string {
	var b strings.Builder
	b.WriteString(Header("AGENTS.md (Codex / OpenAI agents)", tier, len(skills)))
	b.WriteString("Operating contract: you are an autonomous coding agent. Treat the skills\n")
	b.WriteString("below as binding constraints on every commit, PR, or refactor you produce.\n\n")
	for _, s := range skills {
		fmt.Fprintf(&b, "## Skill: %s\n", s.Frontmatter.Title)
		fmt.Fprintf(&b, "Applies to: %s\n\n", strings.Join(s.Frontmatter.AppliesTo, "; "))
		writeMarkdownBullets(&b, "Always", s.Body.Always)
		writeMarkdownBullets(&b, "Never", s.Body.Never)
		if tier != skill.TierMinimal {
			writeMarkdownBullets(&b, "Known false positives", s.Body.KnownFalsePositives)
		}
		if tier == skill.TierFull && s.Body.Context != "" {
			b.WriteString("**Context:**\n\n")
			b.WriteString(s.Body.Context)
			b.WriteString("\n\n")
		}
	}
	b.WriteString(VulnSummary(ctx))
	b.WriteString(GlossaryBlock(ctx))
	b.WriteString(AttackBlock(ctx))
	return b.String()
}
