package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	t.Fatalf("could not find repo root from %s", wd)
	return ""
}

func newLibrary(t *testing.T) *Library {
	t.Helper()
	l, err := NewLibrary(repoRoot(t))
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	return l
}

func TestLookupVulnerabilityFindsEventStream(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.LookupVulnerability("event-stream", "npm", "")
	if err != nil {
		t.Fatalf("LookupVulnerability: %v", err)
	}
	if len(res.Matches) == 0 {
		t.Fatalf("expected event-stream in npm.json; got 0 matches")
	}
	if !strings.EqualFold(res.Matches[0].Name, "event-stream") {
		t.Errorf("first match=%q, want event-stream", res.Matches[0].Name)
	}
	if res.Matches[0].Severity == "" {
		t.Error("match has no severity")
	}
}

func TestLookupVulnerabilityAcrossAllEcosystems(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.LookupVulnerability("event-stream", "", "")
	if err != nil {
		t.Fatalf("LookupVulnerability: %v", err)
	}
	if len(res.Matches) == 0 {
		t.Fatalf("expected at least one match across all ecosystems")
	}
}

func TestLookupVulnerabilityReturnsTyposquats(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.LookupVulnerability("lodash", "npm", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Typosquats) == 0 {
		t.Fatalf("expected at least one typosquat for lodash; got 0")
	}
}

func TestCheckSecretPatternFlagsAWSExampleKeyAsKnownFalsePositive(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckSecretPattern("AKIAIOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) == 0 {
		t.Fatal("expected the canonical AWS docs example to match the AWS Access Key pattern")
	}
	if !res.Matches[0].KnownFalsePositive {
		t.Errorf("AKIAIOSFODNN7EXAMPLE should be flagged as a known false positive")
	}
}

func TestCheckSecretPatternFlagsRealLookingKey(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckSecretPattern("creds: AKIA1234567890ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) == 0 {
		t.Fatal("expected a non-example AKIA key to match")
	}
	if res.Matches[0].KnownFalsePositive {
		t.Errorf("real-looking AKIA key must not be flagged as known false positive")
	}
}

func TestGetSkillTiersDifferInLength(t *testing.T) {
	lib := newLibrary(t)
	minimal, err := lib.GetSkill("secret-detection", "minimal")
	if err != nil {
		t.Fatal(err)
	}
	full, err := lib.GetSkill("secret-detection", "full")
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Content) <= len(minimal.Content) {
		t.Errorf("expected full tier longer than minimal; minimal=%d full=%d",
			len(minimal.Content), len(full.Content))
	}
	if minimal.Title == "" || full.Title == "" {
		t.Errorf("title should be populated; got minimal=%q full=%q", minimal.Title, full.Title)
	}
}

func TestGetSkillDefaultsToCompact(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.GetSkill("secret-detection", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Tier != "compact" {
		t.Errorf("default tier=%q, want compact", res.Tier)
	}
}

func TestGetSkillRejectsUnknownSkill(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.GetSkill("does-not-exist", "compact"); err == nil {
		t.Error("expected error for unknown skill id")
	}
}

func TestSearchSkillsByQuery(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.SearchSkills("secret")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range res.Skills {
		if s.ID == "secret-detection" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("query 'secret' should return secret-detection; got %v", res.Skills)
	}
}

func TestSearchSkillsEmptyReturnsAll(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.SearchSkills("")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skills) < 7 {
		t.Errorf("expected all 7+ skills; got %d", len(res.Skills))
	}
}
