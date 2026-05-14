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
func (l *Library) ScanSecrets(text, filePath string) (*ScanSecretsResult, error) {
	switch {
	case text != "" && filePath != "":
		return nil, fmt.Errorf("scan_secrets: pass either text or file_path, not both")
	case text == "" && filePath == "":
		return nil, fmt.Errorf("scan_secrets: one of text or file_path is required")
	}
	if filePath != "" {
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
type CheckTyposquatResult struct {
	Package    string           `json:"package"`
	Ecosystem  string           `json:"ecosystem,omitempty"`
	Typosquats []TyposquatEntry `json:"typosquats"`
}

// CheckTyposquat returns every typosquat entry where pkg appears as
// either the legitimate target or as a known typosquat. Optionally
// filters by ecosystem.
func (l *Library) CheckTyposquat(pkg, ecosystem string) (*CheckTyposquatResult, error) {
	if strings.TrimSpace(pkg) == "" {
		return nil, fmt.Errorf("check_typosquat: package is required")
	}
	out := &CheckTyposquatResult{Package: pkg, Typosquats: []TyposquatEntry{}}
	if ecosystem != "" {
		eco := strings.ToLower(strings.TrimSpace(ecosystem))
		if !knownEcosystems[eco] {
			return nil, fmt.Errorf("check_typosquat: unknown ecosystem %q", ecosystem)
		}
		out.Ecosystem = eco
		ecosystem = eco
	}
	tf, err := l.loadTyposquats()
	if err != nil {
		return out, nil
	}
	for _, t := range tf.Entries {
		if !strings.EqualFold(t.Target, pkg) && !strings.EqualFold(t.Typosquat, pkg) {
			continue
		}
		if ecosystem != "" && !strings.EqualFold(t.Ecosystem, ecosystem) {
			continue
		}
		out.Typosquats = append(out.Typosquats, t)
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

	cve         *cvePatternsFile
	compliance  map[string]*FrameworkMapping
	sigmaRules  []SigmaRule
	sigmaLoaded bool
}

var extendedCaches sync.Map // *Library → *extendedCache

func (l *Library) extended() *extendedCache {
	// Cache hit is the hot path; avoid allocating a fresh extendedCache
	// (and the empty compliance map it carries) on every loader call by
	// trying Load first and only falling back to LoadOrStore on a miss.
	if v, ok := extendedCaches.Load(l); ok {
		return v.(*extendedCache)
	}
	v, _ := extendedCaches.LoadOrStore(l, &extendedCache{compliance: map[string]*FrameworkMapping{}})
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
