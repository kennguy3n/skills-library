// Package skill parses SKILL.md files into typed structures.
//
// A SKILL.md file consists of a YAML frontmatter block (delimited by `---`
// lines, anchored at the start of the file) followed by a markdown body. The
// body must contain three top-level sections in this order:
//
//	## Rules (for AI agents)
//	## Context (for humans)
//	## References
//
// The Rules section must contain `### ALWAYS`, `### NEVER`, and
// `### KNOWN FALSE POSITIVES` subsections. The parser exposes tier extraction
// helpers (Minimal, Compact, Full) that mirror the compiler's expectations.
package skill

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// FrontmatterRegex is the same line-anchored pattern used by the CI validator.
var FrontmatterRegex = regexp.MustCompile(`(?s)\A---\s*\n(.*?)\n---\s*(?:\n|\z)`)

// TokenBudget declares the token budgets for each tier of a skill.
type TokenBudget struct {
	Minimal int `yaml:"minimal"`
	Compact int `yaml:"compact"`
	Full    int `yaml:"full"`
}

// Frontmatter is the typed view of the YAML frontmatter block.
type Frontmatter struct {
	ID            string      `yaml:"id"`
	Version       string      `yaml:"version"`
	Title         string      `yaml:"title"`
	Description   string      `yaml:"description"`
	Category      string      `yaml:"category"`
	Severity      string      `yaml:"severity"`
	AppliesTo     []string    `yaml:"applies_to"`
	Languages     []string    `yaml:"languages"`
	TokenBudget   TokenBudget `yaml:"token_budget"`
	RulesPath     string      `yaml:"rules_path,omitempty"`
	TestsPath     string      `yaml:"tests_path,omitempty"`
	RelatedSkills []string    `yaml:"related_skills,omitempty"`
	LastUpdated   string      `yaml:"last_updated"`
	Sources       []string    `yaml:"sources"`
	// Language is the BCP-47 locale tag of this SKILL.md (e.g. "es",
	// "zh-Hans"). Only set on files under locales/<bcp47>/<skill-id>/.
	// Empty / unset for the canonical English source under skills/.
	Language string `yaml:"language,omitempty"`
	// SourceRevision pins the English commit a translation was based
	// on (a short or full git SHA). Used by the locale-freshness CI
	// check to warn when the English original drifts.
	SourceRevision string `yaml:"source_revision,omitempty"`
	// Dir overrides the text direction for rendering. Defaults to
	// "ltr". Valid values: "ltr", "rtl". Stub generators set this to
	// "rtl" for right-to-left scripts (Arabic, Hebrew). Downstream
	// compilers MAY use this field when an output format supports a
	// direction hint (e.g. wrapping code blocks in `<div dir="ltr">`
	// inside an RTL doc so identifiers stay legible).
	Dir string `yaml:"dir,omitempty"`
}

// Body contains the parsed markdown body subsections.
type Body struct {
	Title               string
	Always              []string
	Never               []string
	KnownFalsePositives []string
	Context             string
	References          string
	RawRules            string
}

// Skill is the parsed SKILL.md file.
type Skill struct {
	Path        string
	Frontmatter Frontmatter
	Body        Body
}

// AllowedCategories enumerates the only valid `category` values.
var AllowedCategories = map[string]bool{
	"prevention":   true,
	"detection":    true,
	"compliance":   true,
	"supply-chain": true,
	"hardening":    true,
}

// AllowedSeverities enumerates the only valid `severity` values.
var AllowedSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
}

// requiredFields are checked by Validate (mirrors the CI validator).
var requiredFields = []string{
	"id", "version", "title", "description", "category",
	"severity", "applies_to", "languages", "token_budget",
	"last_updated", "sources",
}

// Parse reads a SKILL.md file and returns the typed Skill.
func Parse(path string) (*Skill, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseBytes(path, data)
}

// ParseBytes parses raw SKILL.md bytes.
func ParseBytes(path string, data []byte) (*Skill, error) {
	match := FrontmatterRegex.FindSubmatch(data)
	if match == nil {
		return nil, fmt.Errorf("%s: missing or malformed YAML frontmatter (expected leading and closing '---' lines)", path)
	}

	// Use a raw node first so we can detect missing fields by key presence,
	// not just zero-value comparison.
	var raw map[string]any
	if err := yaml.Unmarshal(match[1], &raw); err != nil {
		return nil, fmt.Errorf("%s: invalid YAML frontmatter: %w", path, err)
	}

	missing := make([]string, 0)
	for _, f := range requiredFields {
		if _, ok := raw[f]; !ok {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%s: missing required frontmatter fields: %v", path, missing)
	}

	var fm Frontmatter
	if err := yaml.Unmarshal(match[1], &fm); err != nil {
		return nil, fmt.Errorf("%s: frontmatter does not match schema: %w", path, err)
	}

	if !AllowedCategories[fm.Category] {
		return nil, fmt.Errorf("%s: invalid category %q (allowed: prevention, detection, compliance, supply-chain, hardening)", path, fm.Category)
	}
	if !AllowedSeverities[fm.Severity] {
		return nil, fmt.Errorf("%s: invalid severity %q (allowed: critical, high, medium, low)", path, fm.Severity)
	}
	if fm.TokenBudget.Minimal <= 0 || fm.TokenBudget.Compact <= 0 || fm.TokenBudget.Full <= 0 {
		return nil, fmt.Errorf("%s: token_budget must declare positive minimal, compact, and full counts", path)
	}
	if fm.Dir != "" && fm.Dir != "ltr" && fm.Dir != "rtl" {
		return nil, fmt.Errorf("%s: invalid dir %q (allowed: ltr, rtl)", path, fm.Dir)
	}

	body := data[len(match[0]):]
	parsed := parseBody(string(body))

	return &Skill{
		Path:        path,
		Frontmatter: fm,
		Body:        parsed,
	}, nil
}

// LoadAll walks a `skills/` root and returns every parsed SKILL.md.
func LoadAll(root string) ([]*Skill, error) {
	skills := make([]*Skill, 0)
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Base(p) != "SKILL.md" {
			return nil
		}
		s, err := Parse(p)
		if err != nil {
			return err
		}
		skills = append(skills, s)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(skills, func(i, j int) bool {
		return skills[i].Frontmatter.ID < skills[j].Frontmatter.ID
	})
	return skills, nil
}

// parseBody walks the markdown body and extracts the three top-level sections.
//
// Body extraction is keyed on the English section headers "## Rules",
// "## Context", and "## References". Localized SKILL.md files under
// `locales/<bcp47>/` that translate these headers (e.g. "## Regeln",
// "## Règles", "## Reglas") will parse with empty Body fields.
// This is intentional: the English file under `skills/<id>/` is the
// canonical source for body content, and translated files are
// presentation-only today. If body-aware processing of translated
// files is ever required, add a per-locale header alias table.
func parseBody(body string) Body {
	out := Body{}
	lines := strings.Split(body, "\n")

	type section int
	const (
		secNone section = iota
		secTitle
		secRules
		secContext
		secRefs
	)

	type subsection int
	const (
		subNone subsection = iota
		subAlways
		subNever
		subFalsePositives
	)

	cur := secNone
	sub := subNone
	var rulesLines, contextLines, refLines []string

	flushBullet := func(line string) (string, bool) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
			return strings.TrimSpace(trimmed[2:]), true
		}
		return "", false
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "# "):
			out.Title = strings.TrimSpace(trimmed[2:])
			cur = secTitle
			sub = subNone
			continue
		case strings.HasPrefix(trimmed, "## Rules"):
			cur = secRules
			sub = subNone
			continue
		case strings.HasPrefix(trimmed, "## Context"):
			cur = secContext
			sub = subNone
			continue
		case strings.HasPrefix(trimmed, "## References"):
			cur = secRefs
			sub = subNone
			continue
		case strings.HasPrefix(trimmed, "## "):
			// Unknown top-level section; ignore but reset.
			cur = secNone
			sub = subNone
			continue
		}

		if cur == secRules {
			rulesLines = append(rulesLines, line)
			switch {
			case strings.HasPrefix(trimmed, "### ALWAYS"):
				sub = subAlways
				continue
			case strings.HasPrefix(trimmed, "### NEVER"):
				sub = subNever
				continue
			case strings.HasPrefix(trimmed, "### KNOWN FALSE POSITIVES"):
				sub = subFalsePositives
				continue
			case strings.HasPrefix(trimmed, "### "):
				sub = subNone
				continue
			}
			if bullet, ok := flushBullet(line); ok {
				switch sub {
				case subAlways:
					out.Always = append(out.Always, bullet)
				case subNever:
					out.Never = append(out.Never, bullet)
				case subFalsePositives:
					out.KnownFalsePositives = append(out.KnownFalsePositives, bullet)
				}
			} else if sub != subNone && trimmed != "" {
				target := pickList(&out, int(sub))
				if target != nil && len(*target) > 0 {
					(*target)[len(*target)-1] = strings.TrimSpace((*target)[len(*target)-1] + " " + trimmed)
				}
			}
		}

		if cur == secContext {
			contextLines = append(contextLines, line)
		}
		if cur == secRefs {
			refLines = append(refLines, line)
		}
	}

	out.RawRules = strings.TrimSpace(strings.Join(rulesLines, "\n"))
	out.Context = strings.TrimSpace(strings.Join(contextLines, "\n"))
	out.References = strings.TrimSpace(strings.Join(refLines, "\n"))
	return out
}

func pickList(b *Body, sub int) *[]string {
	switch sub {
	case int(1):
		return &b.Always
	case int(2):
		return &b.Never
	case int(3):
		return &b.KnownFalsePositives
	}
	return nil
}

// Tier identifies which token-budget tier to extract.
type Tier string

const (
	TierMinimal Tier = "minimal"
	TierCompact Tier = "compact"
	TierFull    Tier = "full"
)

// IsValidTier reports whether the given string is a known tier.
func IsValidTier(t string) bool {
	switch Tier(t) {
	case TierMinimal, TierCompact, TierFull:
		return true
	}
	return false
}

// Extract renders the rule content for the requested tier. The output
// intentionally omits the skill title and description — those are formatter
// concerns. Token counts produced from this function measure the rule body
// only, matching the budgets declared in the SKILL.md frontmatter.
//
//	minimal: ALWAYS + NEVER bullets
//	compact: ALWAYS + NEVER + KNOWN FALSE POSITIVES + References
//	full:    everything (adds Context)
//
// Use ExtractWithHeading when you also want a skill heading prepended for
// display formatters; per-skill token counting uses the bare Extract output so
// formatter chrome does not push a skill over its declared budget.
func (s *Skill) Extract(tier Tier) string {
	var b strings.Builder
	switch tier {
	case TierMinimal:
		writeBullets(&b, "ALWAYS", s.Body.Always)
		writeBullets(&b, "NEVER", s.Body.Never)
	case TierCompact:
		writeBullets(&b, "ALWAYS", s.Body.Always)
		writeBullets(&b, "NEVER", s.Body.Never)
		writeBullets(&b, "KNOWN FALSE POSITIVES", s.Body.KnownFalsePositives)
		if s.Body.References != "" {
			b.WriteString("### References\n")
			b.WriteString(s.Body.References)
			b.WriteString("\n")
		}
	case TierFull:
		writeBullets(&b, "ALWAYS", s.Body.Always)
		writeBullets(&b, "NEVER", s.Body.Never)
		writeBullets(&b, "KNOWN FALSE POSITIVES", s.Body.KnownFalsePositives)
		if s.Body.Context != "" {
			b.WriteString("### Context\n")
			b.WriteString(s.Body.Context)
			b.WriteString("\n\n")
		}
		if s.Body.References != "" {
			b.WriteString("### References\n")
			b.WriteString(s.Body.References)
			b.WriteString("\n")
		}
	}
	return strings.TrimSpace(b.String()) + "\n"
}

// ExtractWithHeading prepends a "## Title" heading and italicized description
// before the tier content, suitable for direct concatenation in display
// formatters.
func (s *Skill) ExtractWithHeading(tier Tier) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", s.Frontmatter.Title)
	fmt.Fprintf(&b, "_%s_\n\n", s.Frontmatter.Description)
	b.WriteString(s.Extract(tier))
	return b.String()
}

func writeBullets(b *strings.Builder, label string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "### %s\n", label)
	for _, item := range items {
		fmt.Fprintf(b, "- %s\n", item)
	}
	b.WriteString("\n")
}

// Validate runs the same checks that Parse does, allowing the caller to verify
// a Skill loaded from another source.
func (s *Skill) Validate() error {
	if s.Frontmatter.ID == "" {
		return fmt.Errorf("%s: missing id", s.Path)
	}
	if !AllowedCategories[s.Frontmatter.Category] {
		return fmt.Errorf("%s: invalid category %q", s.Path, s.Frontmatter.Category)
	}
	if !AllowedSeverities[s.Frontmatter.Severity] {
		return fmt.Errorf("%s: invalid severity %q", s.Path, s.Frontmatter.Severity)
	}
	if s.Frontmatter.Dir != "" && s.Frontmatter.Dir != "ltr" && s.Frontmatter.Dir != "rtl" {
		return fmt.Errorf("%s: invalid dir %q (allowed: ltr, rtl)", s.Path, s.Frontmatter.Dir)
	}
	return nil
}
