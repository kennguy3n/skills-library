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

// TestHotwordNearUTF8ShrinkSafe guards against a panic when strings.ToLower
// shrinks bytes (e.g. U+2126 OHM SIGN → U+03C9 small omega, 3 → 2 bytes). The
// regex match indices come from the original-case text, but the slice operates
// on the lowered text — without clamping, start can exceed len(lowerText).
func TestHotwordNearUTF8ShrinkSafe(t *testing.T) {
	original := "Ω prefix payload aws_key=AKIA suffix"
	lower := strings.ToLower(original)
	// Force matchIdx values that come from the original-length string. After
	// lowering, `lower` is shorter, so start = matchIdx[0] - window may exceed
	// len(lower) once window wraps clamping. We craft a high index past the
	// shrunk lowered length to exercise the upper bound.
	high := len(original) + 5
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("hotwordNear panicked on shrunk lowered text: %v", r)
		}
	}()
	_ = hotwordNear(lower, []int{high, high}, []string{"aws"}, 4)
}
