package cmd

import (
	"strings"
	"testing"
)

func TestTestCmdSecretDetection(t *testing.T) {
	root := repoRoot(t)
	stdout, _, err := executeRoot(t,
		"test", "secret-detection",
		"--library", root,
	)
	if err != nil {
		t.Fatalf("test returned error: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "passed") || !strings.Contains(stdout, "0 failed") {
		t.Errorf("unexpected stdout: %s", stdout)
	}
}

func TestTestCmdUnknownSkill(t *testing.T) {
	root := repoRoot(t)
	_, _, err := executeRoot(t,
		"test", "no-such-skill",
		"--library", root,
	)
	if err == nil {
		t.Fatal("expected error for unknown skill")
	}
}
