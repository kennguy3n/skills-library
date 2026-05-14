// Package tools — extended tool handlers added in v2 of the MCP server.
//
// These handlers back the new tools introduced alongside the MCP
// protocol bump to 2025-11-25: scan_secrets, check_dependency,
// check_typosquat, map_compliance_control, get_sigma_rule, and
// version_status. Each handler reads from the on-disk Skills Library
// the parent Library is rooted at; no network or shell.
package tools

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// placeholderSignature mirrors manifest.PlaceholderSignature in the
// skills-check internal package. Duplicated here because the manifest
// package is internal to skills-check and not importable from
// skills-mcp; the value is part of the on-disk format and changes only
// in a coordinated release.
const placeholderSignature = "TBD"

// rootManifest is the slice of manifest.json this server reads for
// version_status. Mirrors the canonical Manifest struct in the
// skills-check internal/manifest package, narrowed to the fields the
// MCP tool surfaces. Decoding tolerates additional fields.
type rootManifest struct {
	SchemaVersion string     `json:"schema_version"`
	Version       string     `json:"version"`
	ReleasedAt    string     `json:"released_at"`
	Signature     string     `json:"signature"`
	PublicKeyID   string     `json:"public_key_id"`
	Description   string     `json:"description"`
	Files         []struct{} `json:"files"`
}

// maxFileScanBytes caps how large a file scan_secrets will accept. The
// MCP server runs on the user's machine, but the secret-detection
// regexes are not optimised for multi-MB payloads, and an LLM caller
// occasionally passes a binary path by mistake. 10 MiB is generous for
// source code while still bounding the worst case.
const maxFileScanBytes = 10 << 20

// ScanSecretsResult is what the scan_secrets tool returns. When called
// with text, FilePath / FileSize are zero values; when called with a
// file path, Text is empty and the match offsets are relative to the
// file contents.
type ScanSecretsResult struct {
	FilePath string        `json:"file_path,omitempty"`
	FileSize int64         `json:"file_size,omitempty"`
	Matches  []SecretMatch `json:"matches"`
}

// ScanSecrets reads either inline text or a local file and runs the
// secret-detection rules against the contents. Exactly one of text or
// filePath must be non-empty.
//
// When a file_path is supplied it is validated against the Library's
// allowed-roots policy (see SetAllowedRoots) and an unconditional
// deny-list of sensitive system directories (~/.ssh, ~/.aws,
// ~/.gnupg, ~/.kube, ~/.docker, /etc/shadow, /etc/ssh). Both the
// supplied path and its symlink target must satisfy the policy so a
// caller cannot smuggle access via a symlink inside an allowed root.
func (l *Library) ScanSecrets(text, filePath string) (*ScanSecretsResult, error) {
	switch {
	case text != "" && filePath != "":
		return nil, fmt.Errorf("scan_secrets: pass either text or file_path, not both")
	case text == "" && filePath == "":
		return nil, fmt.Errorf("scan_secrets: one of text or file_path is required")
	}
	if filePath != "" {
		if err := l.validateScanPath(filePath); err != nil {
			return nil, err
		}
		st, err := os.Stat(filePath)
		if err != nil {
			return nil, fmt.Errorf("scan_secrets: stat %s: %w", filePath, err)
		}
		if st.IsDir() {
			return nil, fmt.Errorf("scan_secrets: %s is a directory", filePath)
		}
		if st.Size() > maxFileScanBytes {
			return nil, fmt.Errorf("scan_secrets: %s is %d bytes; limit is %d", filePath, st.Size(), maxFileScanBytes)
		}
		// Read through io.LimitReader rather than os.ReadFile so the cap
		// is enforced on the actual bytes returned, not just on the
		// stat'd size. This closes a TOCTOU window where a file (or the
		// target of a symlink) could grow between the Stat above and the
		// read here. Pulling +1 byte past the cap lets us distinguish
		// "exactly at the limit" from "grew past the limit during read".
		f, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("scan_secrets: open %s: %w", filePath, err)
		}
		defer f.Close()
		body, err := io.ReadAll(io.LimitReader(f, maxFileScanBytes+1))
		if err != nil {
			return nil, fmt.Errorf("scan_secrets: read %s: %w", filePath, err)
		}
		if int64(len(body)) > maxFileScanBytes {
			return nil, fmt.Errorf("scan_secrets: %s exceeded %d-byte limit during read", filePath, maxFileScanBytes)
		}
		text = string(body)
		inner, err := l.CheckSecretPattern(text)
		if err != nil {
			return nil, err
		}
		return &ScanSecretsResult{FilePath: filePath, FileSize: int64(len(body)), Matches: inner.Matches}, nil
	}
	inner, err := l.CheckSecretPattern(text)
	if err != nil {
		return nil, err
	}
	return &ScanSecretsResult{Matches: inner.Matches}, nil
}

// CVEPatternMatch is a single CVE pattern entry the check_dependency
// tool surfaces when the package name appears in the CVE name or
// description. Mirrors the shape on disk in
// `vulnerabilities/cve/code-relevant/cve_patterns.json`.
type CVEPatternMatch struct {
	CVE         string   `json:"cve"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Languages   []string `json:"languages,omitempty"`
	AttackType  string   `json:"attack_type,omitempty"`
	References  []string `json:"references,omitempty"`
}

// CheckDependencyResult is what the check_dependency tool returns.
type CheckDependencyResult struct {
	Package    string            `json:"package"`
	Version    string            `json:"version,omitempty"`
	Ecosystem  string            `json:"ecosystem"`
	Malicious  []VulnEntry       `json:"malicious"`
	Typosquats []TyposquatEntry  `json:"typosquats"`
	CVEs       []CVEPatternMatch `json:"cves"`
}

// CheckDependency unifies lookup_vulnerability with CVE-pattern matching
// keyed off the package name. A required ecosystem keeps the answer
// scoped — installers are always ecosystem-specific.
func (l *Library) CheckDependency(pkg, version, ecosystem string) (*CheckDependencyResult, error) {
	if strings.TrimSpace(pkg) == "" {
		return nil, fmt.Errorf("check_dependency: package is required")
	}
	if strings.TrimSpace(ecosystem) == "" {
		return nil, fmt.Errorf("check_dependency: ecosystem is required")
	}
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	if !knownEcosystems[eco] {
		return nil, fmt.Errorf("check_dependency: unknown ecosystem %q", ecosystem)
	}
	inner, err := l.LookupVulnerability(pkg, eco, version)
	if err != nil {
		return nil, err
	}
	out := &CheckDependencyResult{
		Package:    pkg,
		Version:    version,
		Ecosystem:  eco,
		Malicious:  inner.Matches,
		Typosquats: inner.Typosquats,
		CVEs:       []CVEPatternMatch{},
	}
	cve, err := l.loadCVEPatterns()
	if err == nil {
		needle := strings.ToLower(pkg)
		for _, entry := range cve.Entries {
			hay := strings.ToLower(entry.Name + " " + entry.Description)
			if !strings.Contains(hay, needle) {
				continue
			}
			out.CVEs = append(out.CVEs, CVEPatternMatch{
				CVE:         entry.CVE,
				Name:        entry.Name,
				Severity:    entry.Severity,
				Description: entry.Description,
				Languages:   entry.Languages,
				AttackType:  entry.AttackType,
				References:  entry.References,
			})
		}
	}
	return out, nil
}

// CheckTyposquatResult is what the check_typosquat tool returns.
//
// Typosquats lists rows from the curated typosquat database that
// already pin pkg as either the legitimate target or a known squat.
// PotentialTyposquats lists additional candidates discovered at
// runtime by computing the Levenshtein distance between pkg and a
// per-ecosystem popular-packages list — i.e. names the curated DB
// does not (yet) know about but that are within distance 2 of a
// popular package and therefore suspicious.
type CheckTyposquatResult struct {
	Package             string                  `json:"package"`
	Ecosystem           string                  `json:"ecosystem,omitempty"`
	Typosquats          []TyposquatEntry        `json:"typosquats"`
	PotentialTyposquats []PotentialTyposquatHit `json:"potential_typosquats"`
}

// PotentialTyposquatHit is one runtime-discovered candidate: a
// popular package the input is within Levenshtein distance 2 of, but
// is not equal to. Distance 0 (exact match against a popular name) is
// never returned because the caller is most likely already using the
// real package.
type PotentialTyposquatHit struct {
	Target    string `json:"target"`
	Ecosystem string `json:"ecosystem"`
	Distance  int    `json:"levenshtein_distance"`
}

// CheckTyposquat returns every typosquat entry where pkg appears as
// either the legitimate target or as a known typosquat. Optionally
// filters by ecosystem.
//
// In addition to the curated typosquat DB, the function computes the
// Levenshtein distance from pkg to every package on the configured
// popular-packages list for the given ecosystem. Names within
// distance 2 (but not equal to) a popular package are surfaced in
// PotentialTyposquats so the caller can flag a freshly-published
// `requets` / `lodahs` even when no human has added it to the
// curated DB yet.
func (l *Library) CheckTyposquat(pkg, ecosystem string) (*CheckTyposquatResult, error) {
	if strings.TrimSpace(pkg) == "" {
		return nil, fmt.Errorf("check_typosquat: package is required")
	}
	out := &CheckTyposquatResult{
		Package:             pkg,
		Typosquats:          []TyposquatEntry{},
		PotentialTyposquats: []PotentialTyposquatHit{},
	}
	if ecosystem != "" {
		eco := strings.ToLower(strings.TrimSpace(ecosystem))
		if !knownEcosystems[eco] {
			return nil, fmt.Errorf("check_typosquat: unknown ecosystem %q", ecosystem)
		}
		out.Ecosystem = eco
		ecosystem = eco
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
	// Runtime Levenshtein scan against the popular-packages list.
	// Scanning every ecosystem when none is pinned would produce noisy
	// false positives across language boundaries (a npm package name
	// that looks like a PyPI one), so the suggestion-style lookup
	// requires an explicit ecosystem.
	if ecosystem != "" {
		popular, perr := l.loadPopularPackages(ecosystem)
		if perr == nil {
			needle := strings.ToLower(strings.TrimSpace(pkg))
			for _, target := range popular {
				targetLower := strings.ToLower(target)
				if targetLower == needle {
					// Exact match: the caller is using the popular
					// package itself, not a squat.
					continue
				}
				d := levenshtein(needle, targetLower)
				if d > 0 && d <= 2 {
					out.PotentialTyposquats = append(out.PotentialTyposquats, PotentialTyposquatHit{
						Target:    target,
						Ecosystem: ecosystem,
						Distance:  d,
					})
				}
			}
			sort.Slice(out.PotentialTyposquats, func(i, j int) bool {
				if out.PotentialTyposquats[i].Distance != out.PotentialTyposquats[j].Distance {
					return out.PotentialTyposquats[i].Distance < out.PotentialTyposquats[j].Distance
				}
				return out.PotentialTyposquats[i].Target < out.PotentialTyposquats[j].Target
			})
		}
	}
	return out, nil
}

// ComplianceControl is the shape of one row in the compliance/ YAMLs.
// Carries explicit yaml tags to mirror FrameworkMapping; relying on
// yaml.v3's implicit case-insensitive field matching would tie the
// on-disk format to that fallback behaviour.
type ComplianceControl struct {
	ID          string   `json:"id"                    yaml:"id"`
	Title       string   `json:"title"                 yaml:"title"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Skills      []string `json:"skills,omitempty"      yaml:"skills,omitempty"`
	References  []string `json:"references,omitempty"  yaml:"references,omitempty"`
}

// FrameworkMapping is one framework's compliance YAML on disk.
type FrameworkMapping struct {
	SchemaVersion string              `json:"schema_version" yaml:"schema_version"`
	Framework     string              `json:"framework"      yaml:"framework"`
	Version       string              `json:"version"        yaml:"version"`
	LastUpdated   string              `json:"last_updated"   yaml:"last_updated"`
	Controls      []ComplianceControl `json:"controls"       yaml:"controls"`
}

// MapComplianceResult is what the map_compliance_control tool returns.
//
// Frameworks is keyed by the same machine identifier the caller passes
// in `framework` ("soc2", "hipaa", "pci-dss") so the LLM can round-trip
// any key it sees back into a subsequent query. The human-readable
// name ("SOC 2", "HIPAA", "PCI-DSS") is preserved per-entry on the
// FrameworkMatch value.
type MapComplianceResult struct {
	SkillID    string                    `json:"skill_id,omitempty"`
	Query      string                    `json:"query,omitempty"`
	Framework  string                    `json:"framework,omitempty"`
	Frameworks map[string]FrameworkMatch `json:"frameworks"`
}

// FrameworkMatch wraps the controls matched in a single framework with
// the human-readable display name from the YAML.
type FrameworkMatch struct {
	Name     string              `json:"name"`
	Controls []ComplianceControl `json:"controls"`
}

// frameworkFiles maps the framework keys exposed via the MCP tool to
// the on-disk YAML names under compliance/. Keys are stable IDs the
// LLM can pin in `framework` arguments.
var frameworkFiles = map[string]string{
	"soc2":    "soc2_mapping.yaml",
	"hipaa":   "hipaa_mapping.yaml",
	"pci-dss": "pci_dss_mapping.yaml",
}

// frameworkOrder is the deterministic iteration order so tool output is
// stable across calls.
var frameworkOrder = []string{"soc2", "hipaa", "pci-dss"}

// MapComplianceControl finds controls in SOC 2 / HIPAA / PCI DSS that
// reference the supplied skill ID or whose title/description matches
// the free-text query. At least one of skillID or query must be set.
func (l *Library) MapComplianceControl(skillID, query, framework string) (*MapComplianceResult, error) {
	skillID = strings.TrimSpace(skillID)
	query = strings.TrimSpace(query)
	if skillID == "" && query == "" {
		return nil, fmt.Errorf("map_compliance_control: one of skill_id or query is required")
	}
	framework = strings.ToLower(strings.TrimSpace(framework))
	if framework != "" {
		if _, ok := frameworkFiles[framework]; !ok {
			return nil, fmt.Errorf("map_compliance_control: unknown framework %q", framework)
		}
	}
	out := &MapComplianceResult{
		SkillID:    skillID,
		Query:      query,
		Framework:  framework,
		Frameworks: map[string]FrameworkMatch{},
	}
	for _, fwKey := range frameworkOrder {
		if framework != "" && fwKey != framework {
			continue
		}
		mapping, err := l.loadCompliance(fwKey)
		if err != nil {
			continue
		}
		var matches []ComplianceControl
		needle := strings.ToLower(query)
		for _, ctrl := range mapping.Controls {
			matched := false
			if skillID != "" {
				for _, s := range ctrl.Skills {
					if strings.EqualFold(s, skillID) {
						matched = true
						break
					}
				}
			}
			if !matched && query != "" {
				hay := strings.ToLower(ctrl.Title + " " + ctrl.Description)
				if strings.Contains(hay, needle) {
					matched = true
				}
			}
			if matched {
				matches = append(matches, ctrl)
			}
		}
		if matches != nil {
			out.Frameworks[fwKey] = FrameworkMatch{
				Name:     mapping.Framework,
				Controls: matches,
			}
		}
	}
	return out, nil
}

// SigmaRule is the trimmed-down view of a Sigma rule the
// get_sigma_rule tool returns. The Body field is the raw YAML so
// downstream consumers (and humans reading the JSON) can still see the
// full detection logic without re-fetching from disk.
type SigmaRule struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Status      string   `json:"status,omitempty"`
	Level       string   `json:"level,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	References  []string `json:"references,omitempty"`
	Path        string   `json:"path"`
	Category    string   `json:"category"`
	Body        string   `json:"body"`
}

// GetSigmaRuleResult is what the get_sigma_rule tool returns.
type GetSigmaRuleResult struct {
	RuleID   string      `json:"rule_id,omitempty"`
	Query    string      `json:"query,omitempty"`
	Category string      `json:"category,omitempty"`
	Rules    []SigmaRule `json:"rules"`
}

// sigmaCategories pins the allow-list of top-level rules/ subdirs that
// can flow into a filesystem path, mirroring knownEcosystems.
var sigmaCategories = map[string]bool{
	"cloud":     true,
	"container": true,
	"endpoint":  true,
	"saas":      true,
}

// GetSigmaRule returns rules matching ruleID (exact) or query
// (substring) under the rules/ directory. category narrows the search
// to one of the top-level subdirs.
func (l *Library) GetSigmaRule(ruleID, query, category string) (*GetSigmaRuleResult, error) {
	ruleID = strings.TrimSpace(ruleID)
	query = strings.ToLower(strings.TrimSpace(query))
	category = strings.ToLower(strings.TrimSpace(category))
	if ruleID == "" && query == "" {
		return nil, fmt.Errorf("get_sigma_rule: one of rule_id or query is required")
	}
	if category != "" && !sigmaCategories[category] {
		return nil, fmt.Errorf("get_sigma_rule: unknown category %q", category)
	}
	rules, err := l.loadSigmaRules()
	if err != nil {
		return nil, err
	}
	out := &GetSigmaRuleResult{RuleID: ruleID, Query: query, Category: category, Rules: []SigmaRule{}}
	for _, r := range rules {
		if category != "" && !strings.EqualFold(r.Category, category) {
			continue
		}
		if ruleID != "" {
			if strings.EqualFold(r.ID, ruleID) {
				out.Rules = append(out.Rules, r)
			}
			continue
		}
		hay := strings.ToLower(r.ID + " " + r.Title + " " + strings.Join(r.Tags, " "))
		if strings.Contains(hay, query) {
			out.Rules = append(out.Rules, r)
		}
	}
	sort.Slice(out.Rules, func(i, j int) bool { return out.Rules[i].Path < out.Rules[j].Path })
	return out, nil
}

// VersionStatusResult is what the version_status tool returns.
type VersionStatusResult struct {
	SchemaVersion   string `json:"schema_version"`
	Version         string `json:"version"`
	ReleasedAt      string `json:"released_at,omitempty"`
	Description     string `json:"description,omitempty"`
	PublicKeyID     string `json:"public_key_id,omitempty"`
	SignatureStatus string `json:"signature_status"`
	Files           int    `json:"files"`
	ManifestPath    string `json:"manifest_path"`
}

// VersionStatus reads the root manifest.json and surfaces freshness
// and signature state to the caller.
func (l *Library) VersionStatus() (*VersionStatusResult, error) {
	mfPath := filepath.Join(l.root, "manifest.json")
	body, err := os.ReadFile(mfPath)
	if err != nil {
		return nil, fmt.Errorf("version_status: read %s: %w", mfPath, err)
	}
	var m rootManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("version_status: parse %s: %w", mfPath, err)
	}
	status := "signed"
	switch m.Signature {
	case "":
		status = "unsigned"
	case placeholderSignature:
		status = "placeholder"
	}
	return &VersionStatusResult{
		SchemaVersion:   m.SchemaVersion,
		Version:         m.Version,
		ReleasedAt:      m.ReleasedAt,
		Description:     m.Description,
		PublicKeyID:     m.PublicKeyID,
		SignatureStatus: status,
		Files:           len(m.Files),
		ManifestPath:    mfPath,
	}, nil
}

// ----------------------------------------------------------------------
// Caches and loaders for the data backing the new tools. Each loader
// is guarded by its own mutex so callers don't contend with the
// pre-existing skills / vulns / secrets caches.

type cvePatternsFile struct {
	SchemaVersion string `json:"schema_version"`
	LastUpdated   string `json:"last_updated"`
	Description   string `json:"description"`
	Entries       []struct {
		CVE         string   `json:"cve"`
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		References  []string `json:"references"`
		Languages   []string `json:"languages"`
		AttackType  string   `json:"attack_type"`
	} `json:"entries"`
}

// extendedCache backs the per-Library caches for the new tools. The
// mutexes live on the cache itself (rather than as package-level
// globals) so two Library instances under load don't contend on the
// same locks just because they share a process. This matches the
// per-instance pattern used by vulnsMu/secretsMu on the Library type.
type extendedCache struct {
	cveMu        sync.Mutex
	complianceMu sync.Mutex
	sigmaMu      sync.Mutex
	popularMu    sync.Mutex

	cve         *cvePatternsFile
	compliance  map[string]*FrameworkMapping
	sigmaRules  []SigmaRule
	sigmaLoaded bool
	popular     map[string][]string // ecosystem → popular package names
}

var extendedCaches sync.Map // *Library → *extendedCache

func (l *Library) extended() *extendedCache {
	// Cache hit is the hot path; avoid allocating a fresh extendedCache
	// (and the empty compliance map it carries) on every loader call by
	// trying Load first and only falling back to LoadOrStore on a miss.
	if v, ok := extendedCaches.Load(l); ok {
		return v.(*extendedCache)
	}
	v, _ := extendedCaches.LoadOrStore(l, &extendedCache{
		compliance: map[string]*FrameworkMapping{},
		popular:    map[string][]string{},
	})
	return v.(*extendedCache)
}

func (l *Library) loadCVEPatterns() (*cvePatternsFile, error) {
	ec := l.extended()
	ec.cveMu.Lock()
	defer ec.cveMu.Unlock()
	if ec.cve != nil {
		return ec.cve, nil
	}
	path := filepath.Join(l.root, "vulnerabilities", "cve", "code-relevant", "cve_patterns.json")
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f cvePatternsFile
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	ec.cve = &f
	return ec.cve, nil
}

func (l *Library) loadCompliance(fwKey string) (*FrameworkMapping, error) {
	name, ok := frameworkFiles[fwKey]
	if !ok {
		return nil, fmt.Errorf("unknown framework %q", fwKey)
	}
	ec := l.extended()
	ec.complianceMu.Lock()
	defer ec.complianceMu.Unlock()
	if cached, ok := ec.compliance[fwKey]; ok {
		return cached, nil
	}
	path := filepath.Join(l.root, "compliance", name)
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fm FrameworkMapping
	if err := yaml.Unmarshal(body, &fm); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	ec.compliance[fwKey] = &fm
	return &fm, nil
}

// sigmaFileShape is the minimal shape of a Sigma rule on disk we care
// about; YAML lets us decode just these fields and stash the raw bytes
// alongside as Body for downstream callers.
type sigmaFileShape struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Status      string   `yaml:"status"`
	Level       string   `yaml:"level"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
	References  []string `yaml:"references"`
}

func (l *Library) loadSigmaRules() ([]SigmaRule, error) {
	ec := l.extended()
	ec.sigmaMu.Lock()
	defer ec.sigmaMu.Unlock()
	if ec.sigmaLoaded {
		return ec.sigmaRules, nil
	}
	root := filepath.Join(l.root, "rules")
	var rules []SigmaRule
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			return nil
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var raw sigmaFileShape
		if err := yaml.Unmarshal(body, &raw); err != nil {
			return nil // skip malformed rules rather than blow up
		}
		if raw.ID == "" {
			return nil
		}
		rel, err := filepath.Rel(l.root, p)
		if err != nil {
			rel = p
		}
		rel = filepath.ToSlash(rel)
		// Derive category from the first segment after `rules/`.
		parts := strings.SplitN(strings.TrimPrefix(rel, "rules/"), "/", 2)
		category := ""
		if len(parts) > 0 {
			category = parts[0]
		}
		rules = append(rules, SigmaRule{
			ID:          raw.ID,
			Title:       raw.Title,
			Status:      raw.Status,
			Level:       raw.Level,
			Description: raw.Description,
			Tags:        raw.Tags,
			References:  raw.References,
			Path:        rel,
			Category:    category,
			Body:        string(body),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Path < rules[j].Path })
	ec.sigmaRules = rules
	ec.sigmaLoaded = true
	return ec.sigmaRules, nil
}

// loadPopularPackages reads the per-ecosystem top-N package list used
// for runtime Levenshtein typosquat detection. Missing or unparseable
// files produce an empty list rather than an error so the rest of
// CheckTyposquat (the curated DB lookup) keeps working in
// minimally-provisioned environments. The returned slice is cached
// per Library instance.
func (l *Library) loadPopularPackages(ecosystem string) ([]string, error) {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	if !knownEcosystems[eco] {
		return nil, fmt.Errorf("unknown ecosystem %q", ecosystem)
	}
	ec := l.extended()
	ec.popularMu.Lock()
	defer ec.popularMu.Unlock()
	if cached, ok := ec.popular[eco]; ok {
		return cached, nil
	}
	path := filepath.Join(l.root, "vulnerabilities", "supply-chain", "popular-packages", eco+".json")
	body, err := os.ReadFile(path)
	if err != nil {
		// Cache the empty list so we don't re-stat on every call when
		// the optional data file is absent.
		ec.popular[eco] = []string{}
		return ec.popular[eco], nil
	}
	var f struct {
		Ecosystem string   `json:"ecosystem"`
		Packages  []string `json:"packages"`
	}
	if err := json.Unmarshal(body, &f); err != nil {
		ec.popular[eco] = []string{}
		return ec.popular[eco], fmt.Errorf("parse %s: %w", path, err)
	}
	// Defensive dedup: an accidental duplicate entry in the source
	// data would otherwise cause CheckTyposquat to emit duplicate
	// PotentialTyposquats hits with identical Target/Distance fields.
	// Comparison is case-insensitive to match the rest of the lookup
	// pipeline; ordering of the first occurrence is preserved.
	seen := make(map[string]struct{}, len(f.Packages))
	deduped := make([]string, 0, len(f.Packages))
	for _, name := range f.Packages {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, name)
	}
	ec.popular[eco] = deduped
	return ec.popular[eco], nil
}

// levenshtein returns the edit distance between a and b under the
// classic insert / delete / substitute model with unit costs. The
// implementation uses two rolling rows for O(min(len(a), len(b)))
// extra space; for the short package names this is invoked on, that
// is well below the cost of comparing against a hundred popular
// packages per call.
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	// Keep the shorter string as the inner loop to bound memory.
	if len(a) > len(b) {
		a, b = b, a
	}
	prev := make([]int, len(a)+1)
	curr := make([]int, len(a)+1)
	for i := range prev {
		prev[i] = i
	}
	for j := 1; j <= len(b); j++ {
		curr[0] = j
		for i := 1; i <= len(a); i++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			del := prev[i] + 1
			ins := curr[i-1] + 1
			sub := prev[i-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[i] = m
		}
		prev, curr = curr, prev
	}
	return prev[len(a)]
}

// validateScanPath enforces the ScanSecrets access policy: no `..`
// traversal segments in the raw input, no path inside a known
// sensitive system directory, and (when an allow-list is configured
// via SetAllowedRoots) the resolved path must live under one of those
// roots. The check is run on both the supplied path and its
// symlink-resolved counterpart so a symlink inside an allowed root
// cannot redirect the scan to /etc/shadow.
func (l *Library) validateScanPath(p string) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("scan_secrets: file_path is empty")
	}
	if containsTraversal(p) {
		return fmt.Errorf("scan_secrets: file_path may not contain '..' segments: %s", p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return fmt.Errorf("scan_secrets: resolve %s: %w", p, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// Preserve the prior error shape so callers get a useful
		// message; if the file is missing the subsequent os.Stat will
		// say so explicitly.
		resolved = abs
	}
	for _, denied := range sensitiveDirs() {
		if pathUnder(abs, denied) || pathUnder(resolved, denied) {
			return fmt.Errorf("scan_secrets: %s is inside sensitive directory %s", p, denied)
		}
	}
	if len(l.allowedRoots) == 0 {
		return nil
	}
	// AND, not OR: both the raw absolute path and the symlink-resolved
	// path must each be under SOME allowed root. They do NOT need to
	// be the same root. Using OR here would let a symlink planted
	// inside an allowed root redirect the scan to anything outside
	// the deny-list (e.g. ~/.config/<app>/credentials), defeating the
	// whole point of --allowed-roots.
	absAllowed := false
	for _, root := range l.allowedRoots {
		if pathUnder(abs, root) {
			absAllowed = true
			break
		}
	}
	resolvedAllowed := false
	for _, root := range l.allowedRoots {
		if pathUnder(resolved, root) {
			resolvedAllowed = true
			break
		}
	}
	if absAllowed && resolvedAllowed {
		return nil
	}
	return fmt.Errorf("scan_secrets: %s is not under any configured allowed root", p)
}

// containsTraversal reports whether the raw input path contains a
// literal `..` path segment. filepath.Abs would otherwise silently
// normalise these away, masking caller intent.
func containsTraversal(p string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// pathUnder reports whether child is the same path as parent or one
// of its descendants. Both inputs are expected to be cleaned absolute
// paths.
func pathUnder(child, parent string) bool {
	if child == parent {
		return true
	}
	parent = strings.TrimRight(parent, string(filepath.Separator))
	return strings.HasPrefix(child, parent+string(filepath.Separator))
}

// sensitiveDirs returns the absolute directories that ScanSecrets
// must never read from regardless of the allowed-roots configuration.
// Includes the user's SSH / GPG / cloud-CLI credential stores plus a
// handful of system-wide secret stores. The list is built lazily per
// call so a missing home directory does not crash the server.
func sensitiveDirs() []string {
	out := []string{
		"/etc/shadow",
		"/etc/ssh",
		"/etc/gshadow",
		"/root/.ssh",
		"/root/.aws",
		"/root/.gnupg",
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		out = append(out,
			filepath.Join(home, ".ssh"),
			filepath.Join(home, ".gnupg"),
			filepath.Join(home, ".aws"),
			filepath.Join(home, ".kube"),
			filepath.Join(home, ".docker"),
			filepath.Join(home, ".npmrc"),
			filepath.Join(home, ".netrc"),
		)
	}
	return out
}
