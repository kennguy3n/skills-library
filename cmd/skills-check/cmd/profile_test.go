package cmd

import (
	"strings"
	"testing"
)

func TestInitWithProfile(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()
	stdout, _, err := executeRoot(t,
		"init",
		"--library", root,
		"--tool", "universal",
		"--profile", "financial-services",
		"--out", tmp,
		"--no-prompt",
	)
	if err != nil {
		t.Fatalf("init returned error: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "wrote") {
		t.Errorf("unexpected stdout: %s", stdout)
	}
}

func TestInitWithUnknownProfile(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()
	_, _, err := executeRoot(t,
		"init",
		"--library", root,
		"--tool", "universal",
		"--profile", "no-such-profile",
		"--out", tmp,
		"--no-prompt",
	)
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
}


