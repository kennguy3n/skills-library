package skillslib

import (
	"path/filepath"
	"testing"
)

// repoRoot finds the repo root by walking up until go.mod is found.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := filepath.Glob(filepath.Join(dir, "go.mod")); err == nil {
			if matches, _ := filepath.Glob(filepath.Join(dir, "go.mod")); len(matches) > 0 {
				if filepath.Base(dir) == "skills-library" || hasSkillsDir(dir) {
					return dir
				}
			}
		}
	}
	t.Fatalf("could not find repo root")
	return ""
}

func hasSkillsDir(dir string) bool {
	matches, _ := filepath.Glob(filepath.Join(dir, "skills"))
	return len(matches) > 0
}

func TestLoadSkillSecretDetection(t *testing.T) {
	root := repoRoot(t)
	s, err := LoadSkill(filepath.Join(root, "skills", "secret-detection", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Frontmatter.ID != "secret-detection" {
		t.Errorf("unexpected id %q", s.Frontmatter.ID)
	}
	if errs := Validate(s); len(errs) != 0 {
		t.Errorf("expected no validation errors, got %v", errs)
	}
}

func TestLoadAllSkills(t *testing.T) {
	root := repoRoot(t)
	all, err := LoadAll(filepath.Join(root, "skills"))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 20 {
		t.Errorf("expected >=20 skills, got %d", len(all))
	}
}

func TestExtractTiers(t *testing.T) {
	root := repoRoot(t)
	s, err := LoadSkill(filepath.Join(root, "skills", "secret-detection", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	min := Extract(s, TierMinimal)
	compact := Extract(s, TierCompact)
	full := Extract(s, TierFull)
	if len(min) == 0 || len(compact) == 0 || len(full) == 0 {
		t.Fatal("expected non-empty extracts")
	}
	if len(compact) < len(min) {
		t.Errorf("compact (%d) should be >= minimal (%d)", len(compact), len(min))
	}
	if len(full) < len(compact) {
		t.Errorf("full (%d) should be >= compact (%d)", len(full), len(compact))
	}
}

func TestValidateNilSkill(t *testing.T) {
	if errs := Validate(nil); len(errs) != 1 {
		t.Errorf("expected 1 error for nil, got %v", errs)
	}
}
