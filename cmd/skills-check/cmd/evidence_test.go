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

// TestEvidenceCmdJSONEmptySlicesShapeAsArrays verifies that empty per-control
// (PresentSkills, MissingSkills) and top-level (UnmappedSkills,
// UnmappedControls) slices serialize as JSON arrays `[]` rather than `null`.
// Audit consumers and strict JSON-schema validators distinguish the two; the
// report must be shape-stable across emptiness.
func TestEvidenceCmdJSONEmptySlicesShapeAsArrays(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "compliance"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	// One control with no skills mapped + empty library -> every nil-able slice
	// is empty in the output, so any null in the JSON is a regression.
	mapping := `schema_version: "1.0.0"
framework: "TEST"
version: "1.0"
last_updated: "2026-05-13"
controls:
  - id: "CTRL-EMPTY"
    title: "Control with no mapped skills"
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

	// Every nil-able slice must marshal as `[]`. None of the four may render as
	// `null` — Go's encoding/json emits null for nil slices, so a null here is
	// proof the field was never initialized.
	mustHave := []string{
		`"unmapped_skills": []`,
		`"present_skills": []`,
		`"missing_skills": []`,
	}
	for _, want := range mustHave {
		if !strings.Contains(jsonOut, want) {
			t.Errorf("expected JSON to contain %q, got:\n%s", want, jsonOut)
		}
	}
	mustNotHave := []string{
		`"unmapped_skills": null`,
		`"unmapped_controls": null`,
		`"present_skills": null`,
		`"missing_skills": null`,
	}
	for _, bad := range mustNotHave {
		if strings.Contains(jsonOut, bad) {
			t.Errorf("expected JSON to not contain %q (nil-slice marshaling regression), got:\n%s", bad, jsonOut)
		}
	}

	// Round-trip: after Unmarshal of `[]`, slices are non-nil empty;
	// after Unmarshal of `null`, slices are nil. A nil here means the JSON
	// emitted null and the regression slipped past the string checks above.
	var report EvidenceReport
	if err := json.Unmarshal([]byte(jsonOut), &report); err != nil {
		t.Fatalf("failed to parse JSON: %v\n%s", err, jsonOut)
	}
	if report.UnmappedSkills == nil {
		t.Error("UnmappedSkills should be non-nil empty after round-trip")
	}
	if report.UnmappedControls == nil {
		t.Error("UnmappedControls should be non-nil empty after round-trip")
	}
	if len(report.Controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(report.Controls))
	}
	ctrl := report.Controls[0]
	if ctrl.PresentSkills == nil {
		t.Error("PresentSkills should be non-nil empty after round-trip")
	}
	if ctrl.MissingSkills == nil {
		t.Error("MissingSkills should be non-nil empty after round-trip")
	}
}
