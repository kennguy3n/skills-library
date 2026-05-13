package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/kennguy3n/skills-library/internal/skill"
)

// ComplianceMapping is the shape of the per-framework mapping files under
// compliance/<framework>_mapping.yaml.
type ComplianceMapping struct {
	SchemaVersion string `yaml:"schema_version" json:"schema_version"`
	Framework     string `yaml:"framework" json:"framework"`
	Version       string `yaml:"version" json:"version"`
	LastUpdated   string `yaml:"last_updated" json:"last_updated"`
	Controls      []struct {
		ID          string   `yaml:"id" json:"id"`
		Title       string   `yaml:"title" json:"title"`
		Description string   `yaml:"description" json:"description"`
		Skills      []string `yaml:"skills" json:"skills"`
		References  []string `yaml:"references" json:"references"`
	} `yaml:"controls" json:"controls"`
}

// EvidenceReport is the rendered audit artifact for `skills-check evidence`.
type EvidenceReport struct {
	GeneratedAt      time.Time         `json:"generated_at"`
	Framework        string            `json:"framework"`
	FrameworkVersion string            `json:"framework_version,omitempty"`
	LibraryRoot      string            `json:"library_root"`
	SkillsCount      int               `json:"skills_count"`
	Controls         []ControlEvidence `json:"controls"`
	UnmappedSkills   []string          `json:"unmapped_skills"`
	UnmappedControls []string          `json:"unmapped_controls"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

type ControlEvidence struct {
	ID            string         `json:"id"`
	Title         string         `json:"title"`
	Description   string         `json:"description,omitempty"`
	Status        string         `json:"status"` // covered | partial | missing
	MappedSkills  []string       `json:"mapped_skills"`
	PresentSkills []SkillSummary `json:"present_skills"`
	MissingSkills []string       `json:"missing_skills"`
	References    []string       `json:"references,omitempty"`
}

type SkillSummary struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	LastUpdated string `json:"last_updated"`
	Path        string `json:"path"`
}

func evidenceCmd() *cobra.Command {
	var (
		libraryPath string
		framework   string
		format      string
		outFile     string
	)

	c := &cobra.Command{
		Use:   "evidence",
		Short: "Emit a control-coverage audit report mapping installed skills to a compliance framework",
		Long: `Compile an audit-grade evidence report that maps installed skills onto
the controls of a compliance framework (SOC2, HIPAA, PCI-DSS).

The report is timestamped, lists which controls are covered by which skill
versions, flags missing skills, and is suitable for handing to an auditor.
`,
		RunE: func(c *cobra.Command, args []string) error {
			if framework == "" {
				return fmt.Errorf("--framework is required (SOC2|HIPAA|PCI-DSS)")
			}
			fwSlug := strings.ToLower(framework)
			fwSlug = strings.ReplaceAll(fwSlug, "-", "_")

			lib, err := filepath.Abs(libraryPath)
			if err != nil {
				return err
			}

			mappingPath := filepath.Join(lib, "compliance", fwSlug+"_mapping.yaml")
			mapData, err := os.ReadFile(mappingPath)
			if err != nil {
				return fmt.Errorf("read mapping for %s: %w (expected %s)", framework, err, mappingPath)
			}
			var mapping ComplianceMapping
			if err := yaml.Unmarshal(mapData, &mapping); err != nil {
				return fmt.Errorf("parse mapping: %w", err)
			}
			if mapping.SchemaVersion == "" {
				return fmt.Errorf("mapping %s missing schema_version", mappingPath)
			}

			skills, err := skill.LoadAll(filepath.Join(lib, "skills"))
			if err != nil {
				return err
			}
			byID := map[string]*skill.Skill{}
			for _, s := range skills {
				byID[s.Frontmatter.ID] = s
			}

			report := EvidenceReport{
				GeneratedAt:      time.Now().UTC(),
				Framework:        mapping.Framework,
				FrameworkVersion: mapping.Version,
				LibraryRoot:      lib,
				SkillsCount:      len(skills),
				Controls:         make([]ControlEvidence, 0, len(mapping.Controls)),
				Metadata: map[string]string{
					"mapping_schema_version": mapping.SchemaVersion,
					"mapping_last_updated":   mapping.LastUpdated,
				},
			}

			referencedSkills := map[string]bool{}
			for _, ctrl := range mapping.Controls {
				ev := ControlEvidence{
					ID:           ctrl.ID,
					Title:        ctrl.Title,
					Description:  ctrl.Description,
					MappedSkills: append([]string{}, ctrl.Skills...),
					References:   append([]string{}, ctrl.References...),
				}
				for _, sid := range ctrl.Skills {
					referencedSkills[sid] = true
					if s, ok := byID[sid]; ok {
						ev.PresentSkills = append(ev.PresentSkills, SkillSummary{
							ID:          s.Frontmatter.ID,
							Version:     s.Frontmatter.Version,
							LastUpdated: s.Frontmatter.LastUpdated,
							Path:        s.Path,
						})
					} else {
						ev.MissingSkills = append(ev.MissingSkills, sid)
					}
				}
				switch {
				case len(ev.MappedSkills) == 0:
					ev.Status = "unmapped"
				case len(ev.MissingSkills) == 0:
					ev.Status = "covered"
				case len(ev.PresentSkills) == 0:
					ev.Status = "missing"
				default:
					ev.Status = "partial"
				}
				report.Controls = append(report.Controls, ev)
			}

			for _, s := range skills {
				if !referencedSkills[s.Frontmatter.ID] {
					report.UnmappedSkills = append(report.UnmappedSkills, s.Frontmatter.ID)
				}
			}
			sort.Strings(report.UnmappedSkills)

			out, err := renderEvidence(report, format)
			if err != nil {
				return err
			}
			if outFile == "" || outFile == "-" {
				fmt.Fprint(c.OutOrStdout(), out)
			} else {
				if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(outFile, []byte(out), 0o644); err != nil {
					return err
				}
				fmt.Fprintf(c.OutOrStdout(), "wrote evidence report to %s (%d controls)\n", outFile, len(report.Controls))
			}
			return nil
		},
	}

	c.Flags().StringVar(&libraryPath, "library", ".", "Path to the skills library root")
	c.Flags().StringVar(&framework, "framework", "", "Compliance framework: SOC2|HIPAA|PCI-DSS")
	c.Flags().StringVar(&format, "format", "json", "Output format: json|markdown")
	c.Flags().StringVar(&outFile, "out", "", "Write report to this file; '-' or empty for stdout")
	return c
}

func renderEvidence(r EvidenceReport, format string) (string, error) {
	switch strings.ToLower(format) {
	case "json", "":
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	case "markdown", "md":
		return renderEvidenceMarkdown(r), nil
	default:
		return "", fmt.Errorf("unknown format %q (valid: json|markdown)", format)
	}
}

func renderEvidenceMarkdown(r EvidenceReport) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Compliance Evidence Report — %s\n\n", r.Framework)
	if r.FrameworkVersion != "" {
		fmt.Fprintf(&sb, "**Framework version:** %s  \n", r.FrameworkVersion)
	}
	fmt.Fprintf(&sb, "**Generated:** %s  \n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&sb, "**Library root:** `%s`  \n", r.LibraryRoot)
	fmt.Fprintf(&sb, "**Skills installed:** %d  \n", r.SkillsCount)
	fmt.Fprintf(&sb, "**Controls evaluated:** %d\n\n", len(r.Controls))

	var covered, partial, missing int
	for _, c := range r.Controls {
		switch c.Status {
		case "covered":
			covered++
		case "partial":
			partial++
		case "missing":
			missing++
		}
	}
	fmt.Fprintf(&sb, "## Summary\n\n- Covered: %d\n- Partial: %d\n- Missing: %d\n\n", covered, partial, missing)
	fmt.Fprintf(&sb, "## Controls\n\n")
	fmt.Fprintf(&sb, "| Control | Status | Skills present | Skills missing |\n")
	fmt.Fprintf(&sb, "|---|---|---|---|\n")
	for _, c := range r.Controls {
		var present []string
		for _, s := range c.PresentSkills {
			present = append(present, fmt.Sprintf("%s@%s", s.ID, s.Version))
		}
		fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n",
			c.ID, c.Status, strings.Join(present, ", "), strings.Join(c.MissingSkills, ", "))
	}
	if len(r.UnmappedSkills) > 0 {
		fmt.Fprintf(&sb, "\n## Skills not referenced by any control\n\n")
		for _, s := range r.UnmappedSkills {
			fmt.Fprintf(&sb, "- %s\n", s)
		}
	}
	return sb.String()
}
