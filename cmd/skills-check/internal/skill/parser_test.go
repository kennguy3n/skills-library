package skill

import (
	"strings"
	"testing"
)

const validSkill = `---
id: example-skill
version: "1.0.0"
title: "Example Skill"
description: "A skill used to exercise the parser"
category: prevention
severity: high
applies_to:
  - "before every commit"
languages: ["*"]
token_budget:
  minimal: 100
  compact: 400
  full: 1200
rules_path: "rules/"
last_updated: "2026-05-12"
sources:
  - "Test source"
---

# Example Skill

## Rules (for AI agents)

### ALWAYS
- Always do thing one.
- Always do thing two.

### NEVER
- Never do bad thing.

### KNOWN FALSE POSITIVES
- Ignore harmless variant.

## Context (for humans)

This skill demonstrates the parser. The body covers everything the parser
needs to produce all three tiers.

## References

- See the test corpus for verified fixtures.
`

func TestParseValidFrontmatter(t *testing.T) {
	s, err := ParseBytes("example/SKILL.md", []byte(validSkill))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Frontmatter.ID != "example-skill" {
		t.Errorf("id = %q, want example-skill", s.Frontmatter.ID)
	}
	if s.Frontmatter.Category != "prevention" {
		t.Errorf("category = %q", s.Frontmatter.Category)
	}
	if s.Frontmatter.Severity != "high" {
		t.Errorf("severity = %q", s.Frontmatter.Severity)
	}
	if s.Frontmatter.TokenBudget.Minimal != 100 || s.Frontmatter.TokenBudget.Compact != 400 || s.Frontmatter.TokenBudget.Full != 1200 {
		t.Errorf("token_budget mismatch: %+v", s.Frontmatter.TokenBudget)
	}
	if len(s.Body.Always) != 2 {
		t.Errorf("Always count = %d", len(s.Body.Always))
	}
	if len(s.Body.Never) != 1 {
		t.Errorf("Never count = %d", len(s.Body.Never))
	}
	if len(s.Body.KnownFalsePositives) != 1 {
		t.Errorf("KFP count = %d", len(s.Body.KnownFalsePositives))
	}
	if !strings.Contains(s.Body.Context, "This skill demonstrates") {
		t.Errorf("Context missing expected text: %q", s.Body.Context)
	}
	if !strings.Contains(s.Body.References, "test corpus") {
		t.Errorf("References missing expected text: %q", s.Body.References)
	}
}

func TestParseMissingClosingDelimiter(t *testing.T) {
	bad := "---\nid: x\nversion: \"1.0.0\"\ntitle: \"x\"\n# no closing ---\n"
	_, err := ParseBytes("bad.md", []byte(bad))
	if err == nil {
		t.Fatalf("expected error for missing closing ---")
	}
	if !strings.Contains(err.Error(), "frontmatter") {
		t.Errorf("error should mention frontmatter, got %v", err)
	}
}

func TestParseFrontmatterWithDashesInValues(t *testing.T) {
	// Description contains "---" inline. The line-anchored regex must NOT
	// terminate the frontmatter at a non-line-anchored occurrence.
	bodyWithInlineDashes := `---
id: inline-dash
version: "1.0.0"
title: "Inline dash"
description: "before --- after"
category: prevention
severity: medium
applies_to: ["a"]
languages: ["*"]
token_budget:
  minimal: 50
  compact: 200
  full: 500
last_updated: "2026-05-12"
sources: ["s"]
---

# Inline dash

## Rules (for AI agents)
### ALWAYS
- a
### NEVER
- b
### KNOWN FALSE POSITIVES
- c
## Context (for humans)
ctx
## References
ref
`
	s, err := ParseBytes("inline.md", []byte(bodyWithInlineDashes))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Frontmatter.Description != "before --- after" {
		t.Errorf("description not preserved: %q", s.Frontmatter.Description)
	}
}

func TestParseMissingRequiredFields(t *testing.T) {
	missingSeverity := `---
id: x
version: "1.0.0"
title: "x"
description: "x"
category: prevention
applies_to: ["a"]
languages: ["*"]
token_budget:
  minimal: 1
  compact: 2
  full: 3
last_updated: "2026-05-12"
sources: ["s"]
---
body
`
	_, err := ParseBytes("missing.md", []byte(missingSeverity))
	if err == nil {
		t.Fatalf("expected error for missing severity")
	}
	if !strings.Contains(err.Error(), "severity") {
		t.Errorf("error should mention severity, got %v", err)
	}
}

func TestParseInvalidCategory(t *testing.T) {
	bad := strings.Replace(validSkill, "category: prevention", "category: bogus", 1)
	_, err := ParseBytes("bad.md", []byte(bad))
	if err == nil {
		t.Fatalf("expected error for invalid category")
	}
	if !strings.Contains(err.Error(), "category") {
		t.Errorf("error should mention category, got %v", err)
	}
}

func TestParseInvalidSeverity(t *testing.T) {
	bad := strings.Replace(validSkill, "severity: high", "severity: ultra", 1)
	_, err := ParseBytes("bad.md", []byte(bad))
	if err == nil {
		t.Fatalf("expected error for invalid severity")
	}
	if !strings.Contains(err.Error(), "severity") {
		t.Errorf("error should mention severity, got %v", err)
	}
}

func TestBodySectionExtraction(t *testing.T) {
	s, err := ParseBytes("example.md", []byte(validSkill))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Body.Title != "Example Skill" {
		t.Errorf("body title %q", s.Body.Title)
	}
	if !strings.Contains(s.Body.RawRules, "ALWAYS") {
		t.Errorf("RawRules missing ALWAYS section")
	}
	if !strings.Contains(s.Body.RawRules, "KNOWN FALSE POSITIVES") {
		t.Errorf("RawRules missing KFP section")
	}
}

func TestTierExtraction(t *testing.T) {
	s, err := ParseBytes("example.md", []byte(validSkill))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	minimal := s.Extract(TierMinimal)
	compact := s.Extract(TierCompact)
	full := s.Extract(TierFull)

	if !strings.Contains(minimal, "Always do thing one.") {
		t.Errorf("minimal missing always bullet:\n%s", minimal)
	}
	if !strings.Contains(minimal, "Never do bad thing.") {
		t.Errorf("minimal missing never bullet")
	}
	if strings.Contains(minimal, "Ignore harmless variant.") {
		t.Errorf("minimal should NOT contain KFP bullet")
	}
	if !strings.Contains(compact, "Ignore harmless variant.") {
		t.Errorf("compact missing KFP bullet")
	}
	if strings.Contains(compact, "demonstrates the parser") {
		t.Errorf("compact should NOT contain Context block")
	}
	if !strings.Contains(full, "demonstrates the parser") {
		t.Errorf("full missing Context block")
	}
	if len(full) <= len(compact) || len(compact) <= len(minimal) {
		t.Errorf("expected minimal < compact < full, got %d / %d / %d", len(minimal), len(compact), len(full))
	}
}

func TestExtractWithHeading(t *testing.T) {
	s, _ := ParseBytes("example.md", []byte(validSkill))
	out := s.ExtractWithHeading(TierCompact)
	if !strings.HasPrefix(out, "## Example Skill") {
		t.Errorf("ExtractWithHeading should start with title heading, got %q", out[:50])
	}
}

func TestIsValidTier(t *testing.T) {
	cases := map[string]bool{
		"minimal": true,
		"compact": true,
		"full":    true,
		"":        false,
		"unknown": false,
		"COMPACT": false,
	}
	for in, want := range cases {
		if got := IsValidTier(in); got != want {
			t.Errorf("IsValidTier(%q) = %v, want %v", in, got, want)
		}
	}
}
