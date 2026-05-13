package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateRejectsDanglingSkillReferenceInComplianceMapping verifies that
// the validator fails CI when a compliance mapping references a skill ID
// that has no corresponding skills/<id>/SKILL.md. This is the regression
// test for findings like the previously-broken `iam-best-practices`
// reference: a dangling ID would silently flow through to the evidence
// command as falsely-`missing` coverage.
func TestValidateRejectsDanglingSkillReferenceInComplianceMapping(t *testing.T) {
	tmp := buildMinimalLibrary(t)

	// Inject a compliance mapping that points at a skill ID that does not
	// exist in skills/.
	mapping := []byte(`schema_version: "1.0"
framework: "TEST"
version: "test-1.0"
last_updated: "2026-05-13"
controls:
  - id: "CTRL-1"
    title: "Test Control"
    description: "x"
    skills: ["api-security", "no-such-skill-xyz"]
`)
	if err := os.WriteFile(filepath.Join(tmp, "compliance", "test_mapping.yaml"), mapping, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := executeRoot(t, "validate", "--path", tmp)
	if err == nil {
		t.Fatalf("expected validate to fail on dangling skill ID\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "no-such-skill-xyz") {
		t.Errorf("expected stderr to name the dangling ID, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "unknown skill ID") {
		t.Errorf("expected 'unknown skill ID' in stderr, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "control CTRL-1") {
		t.Errorf("expected stderr to name the control, got:\n%s", stderr)
	}
}

// TestValidateRejectsDanglingSkillReferenceInProfile verifies the same
// invariant for profiles/*.yaml (both the top-level skills list and the
// per-control list).
func TestValidateRejectsDanglingSkillReferenceInProfile(t *testing.T) {
	tmp := buildMinimalLibrary(t)

	profile := []byte(`schema_version: "1.0"
name: "test-profile"
description: "x"
last_updated: "2026-05-13"
skills:
  - api-security
  - no-such-skill-in-profile
controls:
  - control_id: "CTRL-2"
    framework: "TEST"
    skills: ["another-missing-skill"]
`)
	if err := os.WriteFile(filepath.Join(tmp, "profiles", "test-profile.yaml"), profile, 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := executeRoot(t, "validate", "--path", tmp)
	if err == nil {
		t.Fatalf("expected validate to fail on dangling profile references; stderr:%s", stderr)
	}
	if !strings.Contains(stderr, "no-such-skill-in-profile") {
		t.Errorf("expected stderr to name the top-level dangling ID, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "another-missing-skill") {
		t.Errorf("expected stderr to name the per-control dangling ID, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "top-level skills list") {
		t.Errorf("expected stderr to label the top-level location, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "control CTRL-2") {
		t.Errorf("expected stderr to label the per-control location, got:\n%s", stderr)
	}
}

// TestValidateAcceptsAllCurrentSkillReferences is the positive-path test:
// the real repository's compliance and profile YAMLs reference only skills
// that exist. This guards against future regressions where a new mapping
// references a skill we forgot to create.
func TestValidateAcceptsAllCurrentSkillReferences(t *testing.T) {
	root := repoRoot(t)
	stdout, stderr, err := executeRoot(t, "validate", "--path", root)
	if err != nil {
		t.Fatalf("validate on real repo failed: %v\nstdout:%s\nstderr:%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "ok:") {
		t.Errorf("expected ok line, got %q", stdout)
	}
}

// buildMinimalLibrary builds a small valid library on disk with one real
// skill (api-security copied from the repo) and the minimum directory
// scaffolding needed for `validate` to run. Returns the absolute path.
func buildMinimalLibrary(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	tmp := t.TempDir()

	for _, sub := range []string{"skills", "compliance", "profiles", "dictionaries", "vulnerabilities"} {
		if err := os.MkdirAll(filepath.Join(tmp, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Copy api-security as the single available skill.
	srcSkill := filepath.Join(root, "skills", "api-security")
	dstSkill := filepath.Join(tmp, "skills", "api-security")
	if err := copyDir(srcSkill, dstSkill); err != nil {
		t.Fatal(err)
	}

	return tmp
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}
