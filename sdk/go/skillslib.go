// Package skillslib is the public Go SDK for the Skills Library.
//
// This package is a thin re-export over the existing internal/skill loader so
// downstream Go programs (Devin agents, custom IDE bridges, security
// dashboards) can load and validate skills without depending on internal
// packages.
//
// Stability: the function signatures here are part of the public API
// surface. The structs they return live under the existing
// github.com/kennguy3n/skills-library/internal/skill package and are
// intentionally re-exported as aliases so a single source of truth defines
// the schema.
package skillslib

import (
	"github.com/kennguy3n/skills-library/internal/skill"
)

// Skill is the parsed representation of a skills/<id>/SKILL.md file. It
// carries both the YAML frontmatter and the prose body.
type Skill = skill.Skill

// Frontmatter is the YAML metadata at the top of a SKILL.md file.
type Frontmatter = skill.Frontmatter

// Tier names the three packaging budgets supported by the library:
// "minimal", "compact", and "full".
type Tier = skill.Tier

const (
	TierMinimal Tier = skill.TierMinimal
	TierCompact Tier = skill.TierCompact
	TierFull    Tier = skill.TierFull
)

// LoadSkill parses a single SKILL.md file from disk and returns the typed
// Skill struct.
func LoadSkill(path string) (*Skill, error) {
	return skill.Parse(path)
}

// LoadAll walks a `skills/` directory tree and returns every parsed
// SKILL.md file it finds.
func LoadAll(dir string) ([]*Skill, error) {
	return skill.LoadAll(dir)
}

// Validate runs the same schema checks the CLI's `skills-check validate`
// command runs against a single skill. It returns a slice of errors, one
// per violation, so callers can present every issue at once. An empty
// slice means the skill is valid.
func Validate(s *Skill) []error {
	if s == nil {
		return []error{errNilSkill}
	}
	if err := s.Validate(); err != nil {
		return []error{err}
	}
	return nil
}

// Extract returns the rendered SKILL.md body for the given tier (minimal /
// compact / full). The result is suitable for direct injection into an LLM
// prompt or for compiling into an IDE-specific configuration file.
func Extract(s *Skill, tier Tier) string {
	if s == nil {
		return ""
	}
	return s.Extract(tier)
}
