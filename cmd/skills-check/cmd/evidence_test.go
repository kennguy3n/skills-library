package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidenceCmdSOC2JSON(t *testing.T) {
	root := repoRoot(t)
	stdout, _, err := executeRoot(t,
		"evidence",
		"--library", root,
		"--framework", "SOC2",
		"--format", "json",
	)
	if err != nil {
		t.Fatalf("evidence returned error: %v\n%s", err, stdout)
	}
	var report EvidenceReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("failed to parse JSON: %v\n%s", err, stdout)
	}
	if report.Framework == "" {
		t.Error("expected framework name")
	}
	if len(report.Controls) == 0 {
		t.Error("expected at least one control")
	}
	if report.SkillsCount < 7 {
		t.Errorf("expected >=7 skills, got %d", report.SkillsCount)
	}
}

func TestEvidenceCmdHIPAAMarkdown(t *testing.T) {
	root := repoRoot(t)
	stdout, _, err := executeRoot(t,
		"evidence",
		"--library", root,
		"--framework", "HIPAA",
		"--format", "markdown",
	)
	if err != nil {
		t.Fatalf("evidence returned error: %v", err)
	}
	if !strings.Contains(stdout, "# Compliance Evidence Report") {
		t.Errorf("missing markdown header: %s", stdout)
	}
	if !strings.Contains(stdout, "HIPAA") {
		t.Errorf("missing framework name: %s", stdout)
	}
}

func TestEvidenceCmdPCIDSS(t *testing.T) {
	root := repoRoot(t)
	stdout, _, err := executeRoot(t,
		"evidence",
		"--library", root,
		"--framework", "PCI-DSS",
		"--format", "json",
	)
	if err != nil {
		t.Fatalf("evidence returned error: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "PCI-DSS") {
		t.Errorf("missing framework name")
	}
}

func TestEvidenceCmdMissingFramework(t *testing.T) {
	root := repoRoot(t)
	_, _, err := executeRoot(t,
		"evidence",
		"--library", root,
	)
	if err == nil {
		t.Fatal("expected error when --framework is missing")
	}
}

func TestEvidenceCmdUnknownFramework(t *testing.T) {
	root := repoRoot(t)
	_, _, err := executeRoot(t,
		"evidence",
		"--library", root,
		"--framework", "NoSuchFramework",
	)
	if err == nil {
		t.Fatal("expected error for unknown framework")
	}
}

// TestEvidenceCmdUnmappedControlsPopulated verifies that controls whose
// skills: list is empty are aggregated into UnmappedControls in the JSON
// report and surfaced in the markdown summary + section. Regression for the
// bug where UnmappedControls was declared but never set.
func TestEvidenceCmdUnmappedControlsPopulated(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "compliance"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	mapping := `schema_version: "1.0.0"
framework: "TEST"
version: "1.0"
last_updated: "2026-05-13"
controls:
  - id: "CTRL-COVERED"
    title: "Covered control"
    skills:
      - "ghost-skill"
  - id: "CTRL-UNMAPPED-A"
    title: "Has no mapped skills A"
    skills: []
  - id: "CTRL-UNMAPPED-B"
    title: "Has no mapped skills B"
    skills: []
`
	if err := os.WriteFile(filepath.Join(dir, "compliance", "test_mapping.yaml"), []byte(mapping), 0o644); err != nil {
		t.Fatal(err)
	}

	jsonOut, _, err := executeRoot(t,
		"evidence",
		"--library", dir,
		"--framework", "TEST",
		"--format", "json",
	)
	if err != nil {
		t.Fatalf("evidence returned error: %v\n%s", err, jsonOut)
	}
	var report EvidenceReport
	if err := json.Unmarshal([]byte(jsonOut), &report); err != nil {
		t.Fatalf("failed to parse JSON: %v\n%s", err, jsonOut)
	}
	if len(report.UnmappedControls) != 2 {
		t.Fatalf("expected 2 UnmappedControls, got %d: %v", len(report.UnmappedControls), report.UnmappedControls)
	}
	if report.UnmappedControls[0] != "CTRL-UNMAPPED-A" || report.UnmappedControls[1] != "CTRL-UNMAPPED-B" {
		t.Errorf("UnmappedControls not sorted as expected: %v", report.UnmappedControls)
	}
	if !strings.Contains(jsonOut, `"unmapped_controls": [`) {
		t.Errorf("expected unmapped_controls array in JSON, got null: %s", jsonOut)
	}

	mdOut, _, err := executeRoot(t,
		"evidence",
		"--library", dir,
		"--framework", "TEST",
		"--format", "markdown",
	)
	if err != nil {
		t.Fatalf("evidence (markdown) returned error: %v\n%s", err, mdOut)
	}
	if !strings.Contains(mdOut, "- Unmapped: 2") {
		t.Errorf("expected markdown summary to include `- Unmapped: 2`, got:\n%s", mdOut)
	}
	if !strings.Contains(mdOut, "## Controls with no mapped skills") {
		t.Errorf("expected markdown to include unmapped-controls section, got:\n%s", mdOut)
	}
	if !strings.Contains(mdOut, "- CTRL-UNMAPPED-A") || !strings.Contains(mdOut, "- CTRL-UNMAPPED-B") {
		t.Errorf("expected both unmapped control IDs listed in markdown, got:\n%s", mdOut)
	}
}
