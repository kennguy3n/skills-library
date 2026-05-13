// Package tools implements the 4 tool handlers exposed by the MCP server.
//
// All tools read from the on-disk Skills Library at the configured root.
// State is loaded lazily and cached for the lifetime of the Library.
package tools

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/kennguy3n/skills-library/internal/skill"
)

// knownEcosystems whitelists the ecosystem identifiers that may flow into
// a filesystem path. Anything else is rejected before reaching disk, so a
// caller can't escape the library root via path traversal (e.g.
// `../../etc/passwd`) by smuggling traversal segments into the
// `ecosystem` argument.
var knownEcosystems = map[string]bool{
	"npm":    true,
	"pypi":   true,
	"crates": true,
	"go":     true,
}

// Library is the live view of a skills-library checkout used to back the
// MCP tools. It owns a cache of parsed skill manifests, vulnerability
// data, and secret-detection rules; reloads are not implemented because
// the MCP server is a short-lived per-session process.
type Library struct {
	root string

	once      sync.Once
	skills    []*skill.Skill
	loadErr   error
	secretsMu sync.Mutex
	secrets   *secretRules
	vulnsMu   sync.Mutex
	vulnCache map[string]*vulnFile
}

// NewLibrary returns a Library rooted at root. It does not eagerly load
// any data; the underlying directories are walked on the first call to
// each tool.
func NewLibrary(root string) (*Library, error) {
	if root == "" {
		return nil, fmt.Errorf("library root is empty")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(abs, "skills")); err != nil {
		return nil, fmt.Errorf("library root %q has no skills/ subdirectory: %w", abs, err)
	}
	return &Library{root: abs, vulnCache: map[string]*vulnFile{}}, nil
}

// Root returns the absolute path of the library checkout this Library
// is reading from.
func (l *Library) Root() string { return l.root }

func (l *Library) loadSkills() ([]*skill.Skill, error) {
	l.once.Do(func() {
		skills, err := skill.LoadAll(filepath.Join(l.root, "skills"))
		if err != nil {
			l.loadErr = err
			return
		}
		l.skills = skills
	})
	return l.skills, l.loadErr
}

// VulnEntry is one entry in a per-ecosystem malicious-packages JSON file.
// Only the fields downstream consumers care about are decoded.
type VulnEntry struct {
	Name             string   `json:"name"`
	VersionsAffected []string `json:"versions_affected,omitempty"`
	Severity         string   `json:"severity"`
	Type             string   `json:"type,omitempty"`
	Description      string   `json:"description,omitempty"`
	References       []string `json:"references,omitempty"`
	CVE              string   `json:"cve,omitempty"`
	AttackType       string   `json:"attack_type,omitempty"`
	Ecosystem        string   `json:"ecosystem,omitempty"`
}

type vulnFile struct {
	Ecosystem string      `json:"ecosystem"`
	Entries   []VulnEntry `json:"entries"`
}

// TyposquatEntry is one row in the typosquat database.
type TyposquatEntry struct {
	Target              string   `json:"target"`
	Typosquat           string   `json:"typosquat"`
	Ecosystem           string   `json:"ecosystem"`
	LevenshteinDistance int      `json:"levenshtein_distance"`
	Status              string   `json:"status"`
	References          []string `json:"references,omitempty"`
}

type typosquatFile struct {
	Entries []TyposquatEntry `json:"entries"`
}

// LookupVulnerabilityResult is what the MCP tool returns.
type LookupVulnerabilityResult struct {
	Package    string           `json:"package"`
	Ecosystem  string           `json:"ecosystem,omitempty"`
	Matches    []VulnEntry      `json:"matches"`
	Typosquats []TyposquatEntry `json:"typosquats"`
}

// LookupVulnerability searches the malicious-packages database for the
// given package name and also returns any matching typosquats. ecosystem
// is optional: empty means search every ecosystem.
func (l *Library) LookupVulnerability(pkg, ecosystem, version string) (*LookupVulnerabilityResult, error) {
	if strings.TrimSpace(pkg) == "" {
		return nil, fmt.Errorf("package is required")
	}
	ecosystems := []string{"npm", "pypi", "crates", "go"}
	if ecosystem != "" {
		eco := strings.ToLower(strings.TrimSpace(ecosystem))
		if !knownEcosystems[eco] {
			return nil, fmt.Errorf("unknown ecosystem %q (must be one of npm, pypi, crates, go)", ecosystem)
		}
		ecosystem = eco
		ecosystems = []string{eco}
	}
	out := &LookupVulnerabilityResult{Package: pkg, Ecosystem: ecosystem, Matches: []VulnEntry{}, Typosquats: []TyposquatEntry{}}
	for _, e := range ecosystems {
		vf, err := l.loadVulnFile(e)
		if err != nil {
			continue
		}
		for _, ent := range vf.Entries {
			if !strings.EqualFold(ent.Name, pkg) {
				continue
			}
			if version != "" && len(ent.VersionsAffected) > 0 {
				if !containsString(ent.VersionsAffected, version) {
					continue
				}
			}
			ent.Ecosystem = e
			out.Matches = append(out.Matches, ent)
		}
	}

	tf, err := l.loadTyposquats()
	if err == nil {
		for _, t := range tf.Entries {
			if !strings.EqualFold(t.Target, pkg) && !strings.EqualFold(t.Typosquat, pkg) {
				continue
			}
			if ecosystem != "" && !strings.EqualFold(t.Ecosystem, ecosystem) {
				continue
			}
			out.Typosquats = append(out.Typosquats, t)
		}
	}
	return out, nil
}

func (l *Library) loadVulnFile(eco string) (*vulnFile, error) {
	if !knownEcosystems[eco] {
		return nil, fmt.Errorf("unknown ecosystem %q", eco)
	}
	l.vulnsMu.Lock()
	defer l.vulnsMu.Unlock()
	if cached, ok := l.vulnCache[eco]; ok {
		return cached, nil
	}
	path := filepath.Join(l.root, "vulnerabilities", "supply-chain", "malicious-packages", eco+".json")
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vf vulnFile
	if err := json.Unmarshal(body, &vf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	l.vulnCache[eco] = &vf
	return &vf, nil
}

func (l *Library) loadTyposquats() (*typosquatFile, error) {
	path := filepath.Join(l.root, "vulnerabilities", "supply-chain", "typosquat-db", "known_typosquats.json")
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tf typosquatFile
	if err := json.Unmarshal(body, &tf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &tf, nil
}

// Pattern is one secret-detection regex paired with metadata used at
// match time.
type Pattern struct {
	Name     string `json:"name"`
	Regex    string `json:"regex"`
	Prefix   string `json:"prefix,omitempty"`
	Severity string `json:"severity"`
	compiled *regexp.Regexp
}

// Exclusion is one entry from dlp_exclusions.json.
type Exclusion struct {
	AppliesTo string   `json:"applies_to"`
	Type      string   `json:"type"`
	Words     []string `json:"words"`
	MatchType string   `json:"match_type"`
}

type secretRules struct {
	Patterns   []*Pattern  `json:"patterns"`
	Exclusions []Exclusion `json:"exclusions"`
}

// SecretMatch is one match returned by CheckSecretPattern.
type SecretMatch struct {
	Name               string `json:"name"`
	Severity           string `json:"severity"`
	Match              string `json:"match"`
	Start              int    `json:"start"`
	End                int    `json:"end"`
	KnownFalsePositive bool   `json:"known_false_positive"`
}

// CheckSecretPatternResult is what the MCP tool returns.
type CheckSecretPatternResult struct {
	Matches []SecretMatch `json:"matches"`
}

// CheckSecretPattern scans text against the secret-detection regex rules
// and returns the matches, flagging any match present in
// dlp_exclusions.json as a known false positive.
func (l *Library) CheckSecretPattern(text string) (*CheckSecretPatternResult, error) {
	rules, err := l.loadSecretRules()
	if err != nil {
		return nil, err
	}
	out := &CheckSecretPatternResult{Matches: []SecretMatch{}}
	if text == "" {
		return out, nil
	}
	for _, p := range rules.Patterns {
		if p.compiled == nil {
			continue
		}
		for _, idx := range p.compiled.FindAllStringIndex(text, -1) {
			m := text[idx[0]:idx[1]]
			out.Matches = append(out.Matches, SecretMatch{
				Name:               p.Name,
				Severity:           p.Severity,
				Match:              m,
				Start:              idx[0],
				End:                idx[1],
				KnownFalsePositive: isKnownFalsePositive(rules.Exclusions, p.Name, m),
			})
		}
	}
	return out, nil
}

func isKnownFalsePositive(exclusions []Exclusion, ruleName, match string) bool {
	for _, e := range exclusions {
		if e.AppliesTo != "*" && !strings.EqualFold(e.AppliesTo, ruleName) {
			continue
		}
		if e.Type != "dictionary" {
			continue
		}
		for _, w := range e.Words {
			switch e.MatchType {
			case "exact":
				if strings.EqualFold(match, w) {
					return true
				}
			case "prefix":
				if strings.HasPrefix(strings.ToLower(match), strings.ToLower(w)) {
					return true
				}
			default:
				if strings.Contains(strings.ToLower(match), strings.ToLower(w)) {
					return true
				}
			}
		}
	}
	return false
}

func (l *Library) loadSecretRules() (*secretRules, error) {
	l.secretsMu.Lock()
	defer l.secretsMu.Unlock()
	if l.secrets != nil {
		return l.secrets, nil
	}
	patternsPath := filepath.Join(l.root, "skills", "secret-detection", "rules", "dlp_patterns.json")
	exclusionsPath := filepath.Join(l.root, "skills", "secret-detection", "rules", "dlp_exclusions.json")
	pBody, err := os.ReadFile(patternsPath)
	if err != nil {
		return nil, err
	}
	var p secretRules
	if err := json.Unmarshal(pBody, &p); err != nil {
		return nil, err
	}
	for _, pat := range p.Patterns {
		re, err := regexp.Compile(pat.Regex)
		if err != nil {
			continue
		}
		pat.compiled = re
	}
	if body, err := os.ReadFile(exclusionsPath); err == nil {
		var x struct {
			Exclusions []Exclusion `json:"exclusions"`
		}
		if err := json.Unmarshal(body, &x); err == nil {
			p.Exclusions = x.Exclusions
		}
	}
	l.secrets = &p
	return l.secrets, nil
}

// GetSkillResult is what the get_skill tool returns.
type GetSkillResult struct {
	SkillID     string `json:"skill_id"`
	Title       string `json:"title"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Tier        string `json:"tier"`
	Content     string `json:"content"`
	Description string `json:"description,omitempty"`
}

// GetSkill loads a skill manifest and returns the requested tier
// content. budget defaults to "compact" when empty.
func (l *Library) GetSkill(skillID, budget string) (*GetSkillResult, error) {
	if skillID == "" {
		return nil, fmt.Errorf("skill_id is required")
	}
	if budget == "" {
		budget = string(skill.TierCompact)
	}
	if !skill.IsValidTier(budget) {
		return nil, fmt.Errorf("invalid budget %q (valid: minimal, compact, full)", budget)
	}
	skills, err := l.loadSkills()
	if err != nil {
		return nil, err
	}
	for _, s := range skills {
		if s.Frontmatter.ID != skillID {
			continue
		}
		return &GetSkillResult{
			SkillID:     skillID,
			Title:       s.Frontmatter.Title,
			Category:    s.Frontmatter.Category,
			Severity:    s.Frontmatter.Severity,
			Tier:        budget,
			Content:     s.Extract(skill.Tier(budget)),
			Description: s.Frontmatter.Description,
		}, nil
	}
	return nil, fmt.Errorf("skill %q not found", skillID)
}

// SkillMeta is one row in a search_skills response.
type SkillMeta struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
}

// SearchSkillsResult is the search_skills response.
type SearchSkillsResult struct {
	Query  string      `json:"query"`
	Skills []SkillMeta `json:"skills"`
}

// SearchSkills returns every skill whose ID, title, description, or
// category contains the query (case-insensitive). An empty query
// returns every skill so the tool also works as a list endpoint.
func (l *Library) SearchSkills(query string) (*SearchSkillsResult, error) {
	skills, err := l.loadSkills()
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(query))
	out := &SearchSkillsResult{Query: query, Skills: []SkillMeta{}}
	for _, s := range skills {
		hay := strings.ToLower(strings.Join([]string{
			s.Frontmatter.ID,
			s.Frontmatter.Title,
			s.Frontmatter.Description,
			s.Frontmatter.Category,
		}, "\n"))
		if q != "" && !strings.Contains(hay, q) {
			continue
		}
		out.Skills = append(out.Skills, SkillMeta{
			ID:          s.Frontmatter.ID,
			Title:       s.Frontmatter.Title,
			Description: s.Frontmatter.Description,
			Category:    s.Frontmatter.Category,
			Severity:    s.Frontmatter.Severity,
		})
	}
	sort.Slice(out.Skills, func(i, j int) bool { return out.Skills[i].ID < out.Skills[j].ID })
	return out, nil
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
