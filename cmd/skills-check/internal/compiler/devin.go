package compiler

import (
	"fmt"
	"strings"

	"github.com/kennguy3n/skills-library/internal/skill"
)

type devinFormatter struct{}

func (devinFormatter) Name() string            { return "devin" }
func (devinFormatter) OutputName() string      { return "devin.md" }
func (devinFormatter) DefaultTier() skill.Tier { return skill.TierFull }

func (devinFormatter) Format(skills []*skill.Skill, tier skill.Tier, ctx Context) string {
	var b strings.Builder
	b.WriteString(Header("Devin", tier, len(skills)))
	b.WriteString("You are working with a larger context window than most assistants. Treat the\n")
	b.WriteString("rules below as binding for every code change, and prefer the rationale in\n")
	b.WriteString("each Context block when making trade-offs.\n\n")
	for _, s := range skills {
		fmt.Fprintf(&b, "## %s\n\n", s.Frontmatter.Title)
		fmt.Fprintf(&b, "**ID:** `%s` — **Category:** %s — **Severity:** %s\n\n", s.Frontmatter.ID, s.Frontmatter.Category, s.Frontmatter.Severity)
		fmt.Fprintf(&b, "_%s_\n\n", s.Frontmatter.Description)
		writeMarkdownBullets(&b, "Always", s.Body.Always)
		writeMarkdownBullets(&b, "Never", s.Body.Never)
		if tier != skill.TierMinimal {
			writeMarkdownBullets(&b, "Known false positives", s.Body.KnownFalsePositives)
		}
		if tier == skill.TierFull && s.Body.Context != "" {
			b.WriteString("**Why this matters:**\n\n")
			b.WriteString(s.Body.Context)
			b.WriteString("\n\n")
		}
		if tier != skill.TierMinimal && s.Body.References != "" {
			b.WriteString("**References:**\n\n")
			b.WriteString(s.Body.References)
			b.WriteString("\n\n")
		}
	}
	b.WriteString(VulnSummary(ctx))
	b.WriteString(GlossaryBlock(ctx))
	b.WriteString(AttackBlock(ctx))
	return b.String()
}
