package cmd

import (
	"encoding/json"
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
