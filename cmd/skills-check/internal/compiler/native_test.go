package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteNativeBundlesEmitsAllThreeTrees(t *testing.T) {
	skills := loadAllSkills(t)
	outDir := t.TempDir()
	if err := WriteNativeBundles(skills, outDir); err != nil {
		t.Fatalf("WriteNativeBundles: %v", err)
	}

	// Every default bundle should produce one directory per skill,
	// each containing SKILL.md + metadata.json.
	for _, bundle := range DefaultNativeBundles {
		t.Run(bundle.Subdir, func(t *testing.T) {
			root := filepath.Join(outDir, bundle.Subdir, bundle.InstallPath)
			for _, s := range skills {
				skillMD := filepath.Join(root, s.Frontmatter.ID, "SKILL.md")
				meta := filepath.Join(root, s.Frontmatter.ID, "metadata.json")
				if info, err := os.Stat(skillMD); err != nil || info.Size() == 0 {
					t.Errorf("missing or empty %s: %v", skillMD, err)
				}
				if info, err := os.Stat(meta); err != nil || info.Size() == 0 {
					t.Errorf("missing or empty %s: %v", meta, err)
				}
			}
		})
	}
}

func TestNativeSkillMDIsPortable(t *testing.T) {
	skills := loadAllSkills(t)
	if len(skills) == 0 {
		t.Skip("no skills available")
	}
	outDir := t.TempDir()
	if err := WriteNativeBundles(skills, outDir); err != nil {
		t.Fatalf("WriteNativeBundles: %v", err)
	}
	s := skills[0]
	for _, bundle := range DefaultNativeBundles {
		p := filepath.Join(outDir, bundle.Subdir, bundle.InstallPath, s.Frontmatter.ID, "SKILL.md")
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		body := string(raw)
		// Native portable frontmatter is just `name` + `description`.
		// Custom fields like severity / token_budget must live in
		// metadata.json, not in the SKILL.md frontmatter — otherwise
		// IDE parsers that enforce the portable schema (e.g. Claude
		// Code) reject the bundle.
		head := body
		if len(head) > 160 {
			head = head[:160]
		}
		if !strings.HasPrefix(body, "---\nname: ") {
			t.Errorf("%s: SKILL.md must start with portable `name:` frontmatter, got:\n%s", bundle.Subdir, head)
		}
		if !strings.Contains(body, "description: ") {
			t.Errorf("%s: SKILL.md missing `description:` frontmatter", bundle.Subdir)
		}
		for _, banned := range []string{"\nseverity:", "\nseverity: ", "\ncategory:", "\ntoken_budget:"} {
			if strings.Contains(body, banned) {
				t.Errorf("%s: SKILL.md contains non-portable frontmatter field %q (must live in metadata.json instead)", bundle.Subdir, strings.TrimPrefix(banned, "\n"))
			}
		}
	}
}

func TestNativeMetadataJSONPreservesFullFrontmatter(t *testing.T) {
	skills := loadAllSkills(t)
	if len(skills) == 0 {
		t.Skip("no skills available")
	}
	outDir := t.TempDir()
	if err := WriteNativeBundles(skills, outDir); err != nil {
		t.Fatalf("WriteNativeBundles: %v", err)
	}
	s := skills[0]
	bundle := DefaultNativeBundles[0]
	p := filepath.Join(outDir, bundle.Subdir, bundle.InstallPath, s.Frontmatter.ID, "metadata.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	var m nativeMetadata
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal metadata.json: %v", err)
	}
	if m.ID != s.Frontmatter.ID {
		t.Errorf("metadata.json id = %q, want %q", m.ID, s.Frontmatter.ID)
	}
	if m.Version != s.Frontmatter.Version {
		t.Errorf("metadata.json version = %q, want %q", m.Version, s.Frontmatter.Version)
	}
	if m.Severity != s.Frontmatter.Severity {
		t.Errorf("metadata.json severity = %q, want %q", m.Severity, s.Frontmatter.Severity)
	}
	if m.TokenBudget.Compact != s.Frontmatter.TokenBudget.Compact {
		t.Errorf("metadata.json token_budget.compact = %d, want %d", m.TokenBudget.Compact, s.Frontmatter.TokenBudget.Compact)
	}
}

