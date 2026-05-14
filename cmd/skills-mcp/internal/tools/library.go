// Package tools implements the 4 tool handlers exposed by the MCP server.
//
// All tools read from the on-disk Skills Library at the configured root.
// State is loaded lazily and cached for the lifetime of the Library.
package tools

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/kennguy3n/skills-library/internal/skill"
)

// knownEcosystems whitelists the ecosystem identifiers that may flow into
// a filesystem path. Anything else is rejected before reaching disk, so a
// caller can't escape the library root via path traversal (e.g.
// `../../etc/passwd`) by smuggling traversal segments into the
// `ecosystem` argument.
//
// The set mirrors the JSON files shipped under
// `vulnerabilities/supply-chain/malicious-packages/<ecosystem>.json`.
var knownEcosystems = map[string]bool{
	"npm":            true,
	"pypi":           true,
	"crates":         true,
	"go":             true,
	"rubygems":       true,
	"maven":          true,
	"nuget":          true,
	"github-actions": true,
	"docker":         true,
}

// allEcosystems is the deterministic ordered list of ecosystem IDs the
// MCP tools iterate when the caller did not pin a specific ecosystem.
// Keep it in sync with knownEcosystems.
var allEcosystems = []string{
	"npm",
	"pypi",
	"crates",
	"go",
	"rubygems",
	"maven",
	"nuget",
	"github-actions",
	"docker",
}

// Library is the live view of a skills-library checkout used to back the
// MCP tools. It owns a cache of parsed skill manifests, vulnerability
// data, and secret-detection rules; reloads are not implemented because
// the MCP server is a short-lived per-session process.
type Library struct {
	root string

	once       sync.Once
	skills     []*skill.Skill
	loadErr    error
	secretsMu  sync.Mutex
	secrets    *secretRules
	vulnsMu    sync.Mutex
	vulnCache  map[string]*vulnFile
	typosquats *typosquatFile

	// allowedRoots, when non-nil and non-empty, restricts ScanSecrets
	// file_path inputs to paths under one of these absolute,
	// symlink-resolved directories. A nil/empty slice preserves the
	// pre-existing "any path on the host" behaviour for backwards
	// compatibility. Sensitive system directories (~/.ssh, ~/.aws,
	// ~/.gnupg, /etc/shadow, ...) are denied regardless.
	allowedRoots []string
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

// SetAllowedRoots scopes ScanSecrets file_path inputs to the given
// directories. Each entry is canonicalised (filepath.Abs +
// EvalSymlinks) so callers can pass relative or symlinked paths.
// Empty entries are skipped. A directory that does not exist is
// rejected so misconfiguration fails loudly at startup rather than
// silently allowing every path through.
//
// Passing an empty (or nil) slice removes the restriction. Calling
// this method is optional; when never invoked, ScanSecrets retains
// its prior behaviour of accepting any absolute path the caller can
// stat.
func (l *Library) SetAllowedRoots(roots []string) error {
	if len(roots) == 0 {
		l.allowedRoots = nil
		return nil
	}
	resolved := make([]string, 0, len(roots))
	for _, r := range roots {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		abs, err := filepath.Abs(r)
		if err != nil {
			return fmt.Errorf("allowed root %q: %w", r, err)
		}
		eval, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return fmt.Errorf("allowed root %q: %w", r, err)
		}
		resolved = append(resolved, eval)
	}
	// A non-empty input whose entries all trim to "" or all fail to
	// resolve must NOT silently disable the policy — that would turn
	// an obvious misconfiguration (e.g. --allowed-roots=" ") into an
	// open-everything posture. Fail loudly instead.
	if len(resolved) == 0 {
		return fmt.Errorf("allowed roots: none of the supplied entries resolved to a valid directory (input=%q)", roots)
	}
	l.allowedRoots = resolved
	return nil
}

// AllowedRoots returns the canonicalised allow-list configured via
// SetAllowedRoots. It returns nil when no restriction is in effect.
func (l *Library) AllowedRoots() []string {
	if len(l.allowedRoots) == 0 {
		return nil
	}
	out := make([]string, len(l.allowedRoots))
	copy(out, l.allowedRoots)
	return out
}

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
	ecosystems := allEcosystems
	if ecosystem != "" {
		eco := strings.ToLower(strings.TrimSpace(ecosystem))
		if !knownEcosystems[eco] {
			return nil, fmt.Errorf("unknown ecosystem %q (must be one of %s)", ecosystem, strings.Join(allEcosystems, ", "))
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
				if !versionInAnyRange(version, ent.VersionsAffected) {
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
	l.vulnsMu.Lock()
	defer l.vulnsMu.Unlock()
	if l.typosquats != nil {
		return l.typosquats, nil
	}
	path := filepath.Join(l.root, "vulnerabilities", "supply-chain", "typosquat-db", "known_typosquats.json")
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tf typosquatFile
	if err := json.Unmarshal(body, &tf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	l.typosquats = &tf
	return &tf, nil
}

// Pattern is one secret-detection regex paired with the runtime
// metadata declared in dlp_patterns.json.
//
// The pattern fields mirror the on-disk schema so CheckSecretPattern
// can apply entropy gating, hotword proximity scoring, and denylist
// filtering at match time rather than relying on the raw regex alone.
type Pattern struct {
	Name               string   `json:"name"`
	Regex              string   `json:"regex"`
	Prefix             string   `json:"prefix,omitempty"`
	Severity           string   `json:"severity"`
	ScoreWeight        float64  `json:"score_weight,omitempty"`
	DenylistSubstrings []string `json:"denylist_substrings,omitempty"`
	Hotwords           []string `json:"hotwords,omitempty"`
	HotwordWindow      int      `json:"hotword_window,omitempty"`
	HotwordBoost       float64  `json:"hotword_boost,omitempty"`
	RequireHotword     bool     `json:"require_hotword,omitempty"`
	EntropyMin         float64  `json:"entropy_min,omitempty"`
	compiled           *regexp.Regexp
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
//
// Score combines the pattern's base score_weight with any
// hotword_boost applied when a contextual hotword was found within
// hotword_window characters of the match. Entropy is the Shannon
// entropy of Match itself (bits/byte), retained on the result so the
// caller can apply its own threshold if it wants something stricter
// than the pattern's entropy_min.
type SecretMatch struct {
	Name               string  `json:"name"`
	Severity           string  `json:"severity"`
	Match              string  `json:"match"`
	Start              int     `json:"start"`
	End                int     `json:"end"`
	KnownFalsePositive bool    `json:"known_false_positive"`
	Score              float64 `json:"score"`
	Entropy            float64 `json:"entropy"`
	HotwordHit         bool    `json:"hotword_hit"`
}

// CheckSecretPatternResult is what the MCP tool returns.
type CheckSecretPatternResult struct {
	Matches []SecretMatch `json:"matches"`
}

// CheckSecretPattern scans text against the secret-detection regex rules
// and returns the matches, flagging any match present in
// dlp_exclusions.json as a known false positive.
//
// In addition to the regex match, each candidate is evaluated against
// the pattern's runtime metadata before it is returned:
//
//   - denylist_substrings: a case-insensitive substring of the
//     denylist drops the candidate (e.g. "EXAMPLE" inside a doc-style
//     AWS key).
//   - entropy_min: the Shannon entropy of the matched substring must
//     meet the threshold. A pattern with no entropy_min skips this
//     check.
//   - hotwords / hotword_window / hotword_boost / require_hotword:
//     when hotwords are defined, the surrounding [-window, +window]
//     characters around the match are scanned for any hotword. If
//     require_hotword is true and none are present, the candidate is
//     dropped; otherwise the hotword_boost is added to the score.
//
// The returned SecretMatch carries the final Score (score_weight plus
// any hotword boost) and the computed Entropy so callers can apply
// their own gating on top.
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
			if containsAnyFold(m, p.DenylistSubstrings) {
				continue
			}
			entropy := shannonEntropy(m)
			if p.EntropyMin > 0 && entropy < p.EntropyMin {
				continue
			}
			hotwordHit := hasHotwordNear(text, idx[0], idx[1], p.Hotwords, p.HotwordWindow)
			if p.RequireHotword && len(p.Hotwords) > 0 && !hotwordHit {
				continue
			}
			score := p.ScoreWeight
			if hotwordHit {
				score += p.HotwordBoost
			}
			out.Matches = append(out.Matches, SecretMatch{
				Name:               p.Name,
				Severity:           p.Severity,
				Match:              m,
				Start:              idx[0],
				End:                idx[1],
				KnownFalsePositive: isKnownFalsePositive(rules.Exclusions, p.Name, m),
				Score:              score,
				Entropy:            entropy,
				HotwordHit:         hotwordHit,
			})
		}
	}
	return out, nil
}

// shannonEntropy returns the byte-level Shannon entropy of s in bits.
// An empty string scores 0. The result is bounded above by 8 because
// the alphabet is one byte wide; secrets dominated by base64-style
// charsets typically score in the 4–6 range, while English prose and
// repeated characters sit below ~4. The entropy_min thresholds in
// dlp_patterns.json are calibrated against this scale.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	e := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// hasHotwordNear scans the text immediately surrounding a match for
// any of the given hotwords. The window is applied on both sides of
// the match. When window is non-positive the check degrades to
// "hotword anywhere in the text" — useful when the caller has already
// scoped the text to a small fragment. An empty hotwords slice
// always returns false.
func hasHotwordNear(text string, start, end int, hotwords []string, window int) bool {
	if len(hotwords) == 0 || text == "" {
		return false
	}
	lo, hi := 0, len(text)
	if window > 0 {
		lo = start - window
		if lo < 0 {
			lo = 0
		}
		hi = end + window
		if hi > len(text) {
			hi = len(text)
		}
	}
	slice := strings.ToLower(text[lo:hi])
	for _, h := range hotwords {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if strings.Contains(slice, h) {
			return true
		}
	}
	return false
}

// containsAnyFold reports whether s contains any of the substrings in
// list using a case-insensitive comparison. An empty list always
// returns false so a pattern without a denylist accepts every match.
func containsAnyFold(s string, list []string) bool {
	if len(list) == 0 {
		return false
	}
	lower := strings.ToLower(s)
	for _, w := range list {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(w)) {
			return true
		}
	}
	return false
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

// versionInAnyRange reports whether the concrete `version` is
// affected by at least one of the declared ranges. See
// versionMatches for the supported range syntax. The function never
// errors: an unparseable range simply does not match.
func versionInAnyRange(version string, affected []string) bool {
	for _, a := range affected {
		if versionMatches(a, version) {
			return true
		}
	}
	return false
}

// versionMatches reports whether `version` falls within the range
// expressed by `affected`. The on-disk versions_affected schema is
// loose, so we accept several practical forms:
//
//   - "all" / "*"            → wildcard, every concrete version matches
//   - "pre-X.Y.Z" / "pre-X"  → matches any version strictly less than X.Y.Z
//   - ">= X.Y.Z", "> X.Y.Z"  → standard semver lower bounds
//   - "<= X.Y.Z", "< X.Y.Z"  → standard semver upper bounds
//   - "X.Y.Z - A.B.C"        → inclusive range, low ≤ version ≤ high
//   - exact "X.Y.Z"          → equality (case-insensitive fallback)
//
// Any input that does not match one of the structured forms falls
// back to case-insensitive string equality, preserving the prior
// containsString behaviour for entries the parser does not recognise.
func versionMatches(affected, version string) bool {
	a := strings.TrimSpace(affected)
	v := strings.TrimSpace(version)
	if a == "" || v == "" {
		return strings.EqualFold(a, v)
	}
	switch strings.ToLower(a) {
	case "all", "*":
		return true
	}
	lower := strings.ToLower(a)
	if strings.HasPrefix(lower, "pre-") {
		return compareSemver(v, strings.TrimSpace(a[4:])) < 0
	}
	switch {
	case strings.HasPrefix(a, ">="):
		return compareSemver(v, strings.TrimSpace(a[2:])) >= 0
	case strings.HasPrefix(a, "<="):
		return compareSemver(v, strings.TrimSpace(a[2:])) <= 0
	case strings.HasPrefix(a, ">"):
		return compareSemver(v, strings.TrimSpace(a[1:])) > 0
	case strings.HasPrefix(a, "<"):
		return compareSemver(v, strings.TrimSpace(a[1:])) < 0
	}
	if i := strings.Index(a, " - "); i > 0 {
		lo := strings.TrimSpace(a[:i])
		hi := strings.TrimSpace(a[i+3:])
		return compareSemver(v, lo) >= 0 && compareSemver(v, hi) <= 0
	}
	// No structured form matched. Try semver equality first so
	// trivially-equivalent encodings like "v1.2.3" / "1.2.3" line up;
	// otherwise fall back to case-insensitive string equality so the
	// legacy exact-match contract still holds for non-semver tags.
	if _, _, _, okA := parseSemver(a); okA {
		if _, _, _, okV := parseSemver(v); okV {
			return compareSemver(a, v) == 0
		}
	}
	return strings.EqualFold(a, v)
}

// compareSemver returns -1, 0, or +1 comparing a to b as semver-ish
// versions. Inputs are tolerated liberally: optional leading "v",
// up to three dotted numeric segments, and any pre-release / build
// suffix stripped before comparison. Unparseable inputs sort as
// equal so an exotic range simply doesn't match instead of crashing.
func compareSemver(a, b string) int {
	am, an, ap, _ := parseSemver(a)
	bm, bn, bp, _ := parseSemver(b)
	switch {
	case am != bm:
		if am < bm {
			return -1
		}
		return 1
	case an != bn:
		if an < bn {
			return -1
		}
		return 1
	case ap != bp:
		if ap < bp {
			return -1
		}
		return 1
	}
	return 0
}

// parseSemver parses a dotted version string into (major, minor,
// patch). Missing trailing segments default to zero so "3" is
// equivalent to "3.0.0". Pre-release (-rc.1) and build (+sha) metadata
// are dropped before parsing. ok reports whether the leading numeric
// part was usable; non-numeric inputs return (0, 0, 0, false).
func parseSemver(v string) (major, minor, patch int, ok bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if i := strings.IndexAny(v, "+-"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return 0, 0, 0, false
	}
	parts := strings.Split(v, ".")
	if len(parts) > 3 {
		return 0, 0, 0, false
	}
	var nums [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return 0, 0, 0, false
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], true
}
