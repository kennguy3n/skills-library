package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kennguy3n/skills-library/internal/skill"
)

// repoRoot walks upward from the test binary cwd to find the repository root.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	t.Fatal("could not find repository root from " + wd)
	return ""
}

func loadAllSkills(t *testing.T) []*skill.Skill {
	t.Helper()
	root := repoRoot(t)
	skills, err := skill.LoadAll(filepath.Join(root, "skills"))
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(skills) == 0 {
		t.Fatal("no skills found")
	}
	return skills
}

func TestEachFormatterProducesOutput(t *testing.T) {
	skills := loadAllSkills(t)
	for _, f := range AllTools() {
		t.Run(f.Name(), func(t *testing.T) {
			out, report, _, err := Compile(skills, f.Name(), f.DefaultTier(), Context{})
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if len(out) < 200 {
				t.Errorf("output suspiciously small: %d bytes", len(out))
			}
			if !strings.Contains(out, "Always") && !strings.Contains(out, "ALWAYS") && !strings.Contains(out, "REQUIRE") {
				t.Errorf("output missing always-style rules")
			}
			if report.Total.OpenAI == 0 {
				t.Errorf("token count not populated")
			}
		})
	}
}

func TestAllSeventSkillsCompile(t *testing.T) {
	skills := loadAllSkills(t)
	if len(skills) < 7 {
		t.Fatalf("expected at least 7 skills, got %d", len(skills))
	}
	for _, tier := range []skill.Tier{skill.TierMinimal, skill.TierCompact, skill.TierFull} {
		_, _, _, err := Compile(skills, "universal", tier, Context{})
		if err != nil {
			t.Errorf("compile universal %s: %v", tier, err)
		}
	}
}

func TestPerSkillBudgetRespected(t *testing.T) {
	skills := loadAllSkills(t)
	_, report, warnings, err := Compile(skills, "claude", skill.TierCompact, Context{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, s := range skills {
		c := report.PerSkill[s.Frontmatter.ID]
		if c.Claude > s.Frontmatter.TokenBudget.Compact {
			t.Errorf("%s compact %d exceeds budget %d", s.Frontmatter.ID, c.Claude, s.Frontmatter.TokenBudget.Compact)
		}
	}
	for _, w := range warnings {
		if strings.Contains(w, "exceeds declared compact budget") {
			t.Errorf("unexpected per-skill warning: %s", w)
		}
	}
}

func TestMissingSkillsDirectory(t *testing.T) {
	dir := t.TempDir()
	skills, err := skill.LoadAll(filepath.Join(dir, "skills"))
	if err == nil && skills != nil {
		// LoadAll should error on missing directory.
	}
	if err == nil {
		t.Errorf("expected error from LoadAll on missing directory")
	}
}

func TestUnknownToolErrors(t *testing.T) {
	skills := loadAllSkills(t)
	_, _, _, err := Compile(skills, "fictional", skill.TierCompact, Context{})
	if err == nil {
		t.Fatalf("expected error for unknown tool")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWriteAllRegeneratesAllEightFiles(t *testing.T) {
	skills := loadAllSkills(t)
	outDir := t.TempDir()
	reports, _, err := WriteAll(skills, Context{}, outDir)
	if err != nil {
		t.Fatalf("WriteAll: %v", err)
	}
	if len(reports) != 8 {
		t.Errorf("expected 8 reports, got %d", len(reports))
	}
	expected := []string{
		"CLAUDE.md", ".cursorrules", "copilot-instructions.md", "AGENTS.md",
		".windsurfrules", "devin.md", ".clinerules", "SECURITY-SKILLS.md",
	}
	for _, name := range expected {
		p := filepath.Join(outDir, name)
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("missing %s: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}

func TestDevinFormatterDefaultsToFull(t *testing.T) {
	if Registry["devin"].DefaultTier() != skill.TierFull {
		t.Errorf("devin should default to full tier")
	}
	for name, f := range Registry {
		if name == "devin" {
			continue
		}
		if f.DefaultTier() == skill.TierFull {
			t.Logf("note: %s also defaults to full tier", name)
		}
	}
}

func TestContextInjection(t *testing.T) {
	skills := loadAllSkills(t)
	ctx := Context{
		VulnerabilitySummary: "- example-package — example description\n",
		GlossaryEntries:      []string{"**SBOM** — bill of materials"},
		AttackTechniques:     []string{"`T1195` Supply Chain Compromise"},
	}
	out, _, _, err := Compile(skills, "claude", skill.TierCompact, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "example-package") {
		t.Errorf("vulnerability summary not injected")
	}
	if !strings.Contains(out, "SBOM") {
		t.Errorf("glossary not injected")
	}
	if !strings.Contains(out, "T1195") {
		t.Errorf("attack techniques not injected")
	}
}

func TestDeterministicOutput(t *testing.T) {
	skills := loadAllSkills(t)
	a, _, _, err := Compile(skills, "claude", skill.TierCompact, Context{})
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, err := Compile(skills, "claude", skill.TierCompact, Context{})
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("compile output is not deterministic")
	}
}
