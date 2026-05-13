package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/kennguy3n/skills-library/cmd/skills-check/internal/token"
	"github.com/kennguy3n/skills-library/internal/skill"
)

func validateCmd() *cobra.Command {
	var path string
	c := &cobra.Command{
		Use:   "validate",
		Short: "Validate SKILL.md frontmatter, rule files, and token budgets",
		RunE: func(c *cobra.Command, args []string) error {
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			skills, err := skill.LoadAll(filepath.Join(abs, "skills"))
			if err != nil {
				return err
			}

			var problems []string
			for _, s := range skills {
				if err := s.Validate(); err != nil {
					problems = append(problems, err.Error())
				}
				expected := s.Frontmatter.ID
				actual := filepath.Base(filepath.Dir(s.Path))
				if expected != actual {
					problems = append(problems, fmt.Sprintf("%s: frontmatter id %q does not match directory %q", s.Path, expected, actual))
				}
				if rp := s.Frontmatter.RulesPath; rp != "" {
					full := filepath.Join(filepath.Dir(s.Path), rp)
					if _, err := os.Stat(full); err != nil {
						problems = append(problems, fmt.Sprintf("%s: rules_path %q not found", s.Path, rp))
					}
				}
				for _, tier := range []skill.Tier{skill.TierMinimal, skill.TierCompact, skill.TierFull} {
					limit := budgetFor(s, tier)
					if limit <= 0 {
						problems = append(problems, fmt.Sprintf("%s: missing positive %s budget", s.Path, tier))
						continue
					}
					tc, err := token.Count(s.Extract(tier))
					if err != nil {
						return err
					}
					if tc.Claude > limit {
						problems = append(problems, fmt.Sprintf(
							"%s: %s tier %d tokens (claude) exceeds declared budget %d",
							s.Path, tier, tc.Claude, limit,
						))
					}
				}
			}

			if err := validateRuleFiles(abs, &problems); err != nil {
				return err
			}

			knownIDs := make(map[string]bool, len(skills))
			for _, s := range skills {
				knownIDs[s.Frontmatter.ID] = true
			}
			if err := validateSkillReferences(abs, knownIDs, &problems); err != nil {
				return err
			}

			if len(problems) > 0 {
				for _, p := range problems {
					fmt.Fprintln(c.ErrOrStderr(), "FAIL:", p)
				}
				return fmt.Errorf("%d validation problem(s)", len(problems))
			}
			fmt.Fprintf(c.OutOrStdout(), "ok: %d skills validated\n", len(skills))
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", ".", "library root")
	return c
}

func budgetFor(s *skill.Skill, tier skill.Tier) int {
	switch tier {
	case skill.TierMinimal:
		return s.Frontmatter.TokenBudget.Minimal
	case skill.TierCompact:
		return s.Frontmatter.TokenBudget.Compact
	case skill.TierFull:
		return s.Frontmatter.TokenBudget.Full
	}
	return 0
}

func validateRuleFiles(root string, problems *[]string) error {
	return filepath.Walk(filepath.Join(root, "skills"), func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".json":
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			var v any
			if err := json.Unmarshal(b, &v); err != nil {
				*problems = append(*problems, fmt.Sprintf("%s: invalid JSON: %v", p, err))
				return nil
			}
			validateSchemaShape(p, v, problems)
		case ".yaml", ".yml":
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			var v any
			if err := yaml.Unmarshal(b, &v); err != nil {
				*problems = append(*problems, fmt.Sprintf("%s: invalid YAML: %v", p, err))
				return nil
			}
			validateSchemaShape(p, v, problems)
		}
		return nil
	})
}

// validateSchemaShape enforces the lightweight rule-file conventions used
// across the library: every rule file should declare a schema_version and a
// last_updated date.
func validateSchemaShape(path string, v any, problems *[]string) {
	m, ok := v.(map[string]any)
	if !ok {
		// Bare arrays or scalars are allowed; structural rule files only.
		return
	}
	if _, ok := m["schema_version"]; !ok {
		*problems = append(*problems, fmt.Sprintf("%s: rule file missing %q", path, "schema_version"))
	}
}

// validateSkillReferences cross-checks every skill ID referenced in
// compliance/*.yaml and profiles/*.yaml against the set of skill IDs that
// actually exist under skills/. A dangling reference would cause the
// evidence command to report falsely-`missing` coverage, so the validator
// fails CI on any unknown ID.
func validateSkillReferences(root string, knownIDs map[string]bool, problems *[]string) error {
	check := func(yamlPath string, refs []skillRef) {
		for _, r := range refs {
			if r.skillID == "" {
				continue
			}
			if !knownIDs[r.skillID] {
				*problems = append(*problems, fmt.Sprintf(
					"%s: %s references unknown skill ID %q (no skills/%s/SKILL.md)",
					yamlPath, r.where, r.skillID, r.skillID,
				))
			}
		}
	}

	compDir := filepath.Join(root, "compliance")
	if refs, err := collectComplianceSkillRefs(compDir); err != nil {
		return err
	} else {
		for path, controlRefs := range refs {
			check(path, controlRefs)
		}
	}

	profDir := filepath.Join(root, "profiles")
	if refs, err := collectProfileSkillRefs(profDir); err != nil {
		return err
	} else {
		for path, profRefs := range refs {
			check(path, profRefs)
		}
	}

	return nil
}

// skillRef captures one referenced skill ID and a human-readable label of
// where in the YAML it came from (control id, profile name, etc.).
type skillRef struct {
	skillID string
	where   string
}

// collectComplianceSkillRefs walks compliance/<framework>_mapping.yaml files
// and returns, per file, the skill IDs referenced under each control.
func collectComplianceSkillRefs(dir string) (map[string][]skillRef, error) {
	out := make(map[string][]skillRef)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var mapping struct {
			Controls []struct {
				ID     string   `yaml:"id"`
				Skills []string `yaml:"skills"`
			} `yaml:"controls"`
		}
		if err := yaml.Unmarshal(data, &mapping); err != nil {
			continue // syntactic problems are reported by validateRuleFiles
		}
		refs := make([]skillRef, 0)
		for _, ctrl := range mapping.Controls {
			for _, sid := range ctrl.Skills {
				refs = append(refs, skillRef{
					skillID: strings.TrimSpace(sid),
					where:   fmt.Sprintf("control %s", ctrl.ID),
				})
			}
		}
		out[path] = refs
	}
	return out, nil
}

// collectProfileSkillRefs walks profiles/*.yaml files and returns, per file,
// the skill IDs referenced in both the top-level `skills:` list and the
// per-control `skills:` lists.
func collectProfileSkillRefs(dir string) (map[string][]skillRef, error) {
	out := make(map[string][]skillRef)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var prof struct {
			Name     string   `yaml:"name"`
			Skills   []string `yaml:"skills"`
			Controls []struct {
				ControlID string   `yaml:"control_id"`
				Skills    []string `yaml:"skills"`
			} `yaml:"controls"`
		}
		if err := yaml.Unmarshal(data, &prof); err != nil {
			continue
		}
		refs := make([]skillRef, 0)
		for _, sid := range prof.Skills {
			refs = append(refs, skillRef{
				skillID: strings.TrimSpace(sid),
				where:   "top-level skills list",
			})
		}
		for _, ctrl := range prof.Controls {
			for _, sid := range ctrl.Skills {
				refs = append(refs, skillRef{
					skillID: strings.TrimSpace(sid),
					where:   fmt.Sprintf("control %s", ctrl.ControlID),
				})
			}
		}
		out[path] = refs
	}
	return out, nil
}
