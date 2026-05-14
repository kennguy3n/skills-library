package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanSecretsRejectsBothInputs(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.ScanSecrets("", ""); err == nil {
		t.Error("scan_secrets must reject empty input")
	}
	if _, err := lib.ScanSecrets("x", "/tmp/x"); err == nil {
		t.Error("scan_secrets must reject both text and file_path")
	}
}

func TestScanSecretsTextDelegatesToCheckSecretPattern(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.ScanSecrets("creds: AKIA1234567890ABCDEF", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) == 0 {
		t.Error("expected a match for a real-looking AKIA key")
	}
	if res.FilePath != "" || res.FileSize != 0 {
		t.Error("file fields should be zero for inline text scan")
	}
}

func TestScanSecretsFile(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "leak.txt")
	if err := os.WriteFile(path, []byte("creds: AKIA1234567890ABCDEF\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := lib.ScanSecrets("", path)
	if err != nil {
		t.Fatal(err)
	}
	if res.FilePath != path {
		t.Errorf("file_path=%q want %q", res.FilePath, path)
	}
	if res.FileSize == 0 {
		t.Error("file_size should be > 0")
	}
	if len(res.Matches) == 0 {
		t.Error("expected at least one match in scanned file")
	}
}

func TestCheckDependencyNeedsEcosystem(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.CheckDependency("event-stream", "", ""); err == nil {
		t.Error("check_dependency must require ecosystem")
	}
	if _, err := lib.CheckDependency("", "", "npm"); err == nil {
		t.Error("check_dependency must require package")
	}
}

func TestCheckDependencyEventStreamNpm(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckDependency("event-stream", "", "npm")
	if err != nil {
		t.Fatal(err)
	}
	if res.Ecosystem != "npm" {
		t.Errorf("ecosystem=%q want npm", res.Ecosystem)
	}
	if len(res.Malicious) == 0 {
		t.Fatal("expected at least one malicious entry for event-stream/npm")
	}
}

func TestCheckTyposquatLodash(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckTyposquat("lodash", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Typosquats) == 0 {
		t.Error("expected at least one typosquat row for lodash")
	}
}

func TestMapComplianceControlBySkill(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.MapComplianceControl("secret-detection", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Frameworks) == 0 {
		t.Fatal("expected secret-detection to map to at least one framework")
	}
}

func TestMapComplianceControlRequiresInput(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.MapComplianceControl("", "", ""); err == nil {
		t.Error("map_compliance_control must require skill_id or query")
	}
	if _, err := lib.MapComplianceControl("x", "", "not-a-real-framework"); err == nil {
		t.Error("map_compliance_control must reject unknown framework")
	}
}

func TestMapComplianceControlByQueryAndFramework(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.MapComplianceControl("", "encryption", "pci-dss")
	if err != nil {
		t.Fatal(err)
	}
	// PCI DSS has multiple controls mentioning encryption; just assert
	// the framework filter actually narrowed the result set.
	if len(res.Frameworks) > 1 {
		t.Errorf("framework filter should yield at most one framework, got %v", res.Frameworks)
	}
}

// TestMapComplianceControlResponseKeyShape pins down the response
// shape post-review-flag-4: the Frameworks map MUST be keyed by the
// same machine ID the caller would pass in `framework` ("soc2" /
// "hipaa" / "pci-dss") and each entry MUST carry the human-readable
// name in its own field. An LLM client should be able to round-trip
// any key it sees back into a follow-up MapComplianceControl call.
func TestMapComplianceControlResponseKeyShape(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.MapComplianceControl("secret-detection", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Frameworks) == 0 {
		t.Fatal("expected at least one framework match for secret-detection")
	}
	validKeys := map[string]bool{"soc2": true, "hipaa": true, "pci-dss": true}
	for k, v := range res.Frameworks {
		if !validKeys[k] {
			t.Errorf("framework key %q is not a machine identifier; expected one of %v", k, validKeys)
		}
		if v.Name == "" {
			t.Errorf("framework %q must populate its human-readable Name field", k)
		}
		if len(v.Controls) == 0 {
			t.Errorf("framework %q matched but Controls slice is empty", k)
		}
	}
}

func TestGetSigmaRuleByQuery(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.GetSigmaRule("", "s3", "cloud")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) == 0 {
		t.Fatal("expected at least one Sigma rule matching s3 under cloud/")
	}
	found := false
	for _, r := range res.Rules {
		if strings.Contains(strings.ToLower(r.Title), "s3") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected an s3 rule in results; got %v", res.Rules)
	}
}

func TestGetSigmaRuleRequiresInput(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.GetSigmaRule("", "", ""); err == nil {
		t.Error("get_sigma_rule must require rule_id or query")
	}
	if _, err := lib.GetSigmaRule("", "x", "not-a-real-category"); err == nil {
		t.Error("get_sigma_rule must reject unknown category")
	}
}

func TestVersionStatusReadsRootManifest(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.VersionStatus()
	if err != nil {
		t.Fatal(err)
	}
	if res.Version == "" {
		t.Error("version_status: version should be populated from manifest.json")
	}
	if res.Files == 0 {
		t.Error("version_status: files count should be > 0")
	}
	switch res.SignatureStatus {
	case "signed", "unsigned", "placeholder":
		// ok
	default:
		t.Errorf("unexpected signature_status %q", res.SignatureStatus)
	}
}

func TestCheckDependencyRejectsUnknownEcosystem(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.CheckDependency("foo", "", "rubbish"); err == nil {
		t.Error("check_dependency must reject unknown ecosystem")
	}
}

// LookupVulnerability still rejects the new ecosystems' aliases? Cover
// one of the new ecosystems for parity.
func TestLookupVulnerabilityAcceptsRubygems(t *testing.T) {
	lib := newLibrary(t)
	// Even if there is no malicious-packages hit, the lookup should
	// not fail for a known ecosystem.
	if _, err := lib.LookupVulnerability("rails", "rubygems", ""); err != nil {
		t.Errorf("LookupVulnerability with rubygems should not error: %v", err)
	}
}

// TestLevenshtein covers a handful of obvious cases and the
// case-folded contract upstream callers rely on. The function itself
// does not fold case; callers (CheckTyposquat) normalise to lowercase
// before calling.
func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "abc", 3},
		{"lodash", "lodahs", 2},
		{"requests", "requets", 1},
		{"requests", "request", 1},
		{"react", "react", 0},
		{"abcdef", "abcxyz", 3},
	}
	for _, tc := range cases {
		if got := levenshtein(tc.a, tc.b); got != tc.want {
			t.Errorf("levenshtein(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestCheckTyposquatPotentialFromPopularList exercises the new
// runtime path: an off-by-one variant of `requests` (PyPI) is not in
// the curated DB but is within Levenshtein distance 1 of the popular
// name and must therefore surface as a potential typosquat.
func TestCheckTyposquatPotentialFromPopularList(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckTyposquat("requets", "pypi")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range res.PotentialTyposquats {
		if p.Target == "requests" && p.Distance > 0 && p.Distance <= 2 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected `requests` to surface as a potential typosquat for `requets`; got %+v", res.PotentialTyposquats)
	}
}

// TestCheckTyposquatExactPopularDoesNotSurface confirms an exact
// match against the popular-packages list is NOT flagged as a
// potential typosquat (distance 0 is excluded).
func TestCheckTyposquatExactPopularDoesNotSurface(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckTyposquat("react", "npm")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range res.PotentialTyposquats {
		if strings.EqualFold(p.Target, "react") {
			t.Errorf("exact match against popular list should not surface; got %+v", p)
		}
	}
}

// TestScanSecretsAllowedRootsRestriction confirms file_path is
// rejected when it falls outside the configured allow-list.
func TestScanSecretsAllowedRootsRestriction(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	inside := filepath.Join(dir, "leak.txt")
	if err := os.WriteFile(inside, []byte("creds: AKIA1234567890ABCDEF\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := lib.SetAllowedRoots([]string{dir}); err != nil {
		t.Fatalf("SetAllowedRoots: %v", err)
	}
	// Path inside the allowed root: ok.
	if _, err := lib.ScanSecrets("", inside); err != nil {
		t.Errorf("path inside allowed root should be accepted: %v", err)
	}
	// Path outside the allowed root: denied.
	outside := filepath.Join(other, "leak.txt")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.ScanSecrets("", outside); err == nil {
		t.Errorf("path outside allowed root should be denied")
	}
}

// TestScanSecretsSensitiveDirAlwaysDenied confirms ~/.ssh-like
// directories are denied regardless of the allow-list state.
func TestScanSecretsSensitiveDirAlwaysDenied(t *testing.T) {
	lib := newLibrary(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory available")
	}
	target := filepath.Join(home, ".ssh", "id_rsa")
	if _, err := lib.ScanSecrets("", target); err == nil {
		t.Errorf("scan_secrets must deny paths inside ~/.ssh even without an allow-list")
	}
}

// TestScanSecretsTraversalRejected covers raw `..` segments. Even
// without an allow-list these are rejected so a caller cannot use
// path traversal to escape the directory their MCP client believed
// it had restricted them to.
func TestScanSecretsTraversalRejected(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.ScanSecrets("", "/tmp/../etc/passwd"); err == nil {
		t.Errorf("scan_secrets must reject paths containing '..' segments")
	}
}

// TestScanSecretsSARIFRoundTrip verifies the SARIF wrapper carries
// the expected metadata for an inline-text scan and survives JSON
// marshalling without panicking.
func TestScanSecretsSARIFRoundTrip(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.ScanSecrets("creds: AKIA1234567890ABCDEF", "")
	if err != nil {
		t.Fatal(err)
	}
	log := ScanSecretsSARIF(res)
	if log.Version != SARIFVersion {
		t.Errorf("sarif version = %q, want %q", log.Version, SARIFVersion)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected one SARIF run, got %d", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Name != SARIFToolName {
		t.Errorf("driver name = %q, want %q", log.Runs[0].Tool.Driver.Name, SARIFToolName)
	}
	if len(log.Runs[0].Results) == 0 {
		t.Errorf("expected at least one SARIF result")
	}
	if _, err := json.Marshal(log); err != nil {
		t.Errorf("marshalling SARIF log: %v", err)
	}
}

// TestCheckDependencySARIFShape pins the SARIF driver / rule
// identifiers for check_dependency so downstream filters do not
// silently drift.
func TestCheckDependencySARIFShape(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.CheckDependency("event-stream", "3.3.6", "npm")
	if err != nil {
		t.Fatal(err)
	}
	log := CheckDependencySARIF(res)
	if log.Runs[0].Tool.Driver.Name != SARIFToolName {
		t.Errorf("driver name = %q", log.Runs[0].Tool.Driver.Name)
	}
	wantIDs := map[string]bool{
		"skills-mcp.malicious-package": true,
		"skills-mcp.typosquat":         true,
		"skills-mcp.cve-pattern":       true,
	}
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if !wantIDs[r.ID] {
			t.Errorf("unexpected SARIF rule id %q", r.ID)
		}
	}
	if _, err := json.Marshal(log); err != nil {
		t.Errorf("marshal: %v", err)
	}
}

// TestLookupVulnerabilitySemverRange exercises the new semver-aware
// version matcher end-to-end. event-stream@3.3.6 is the only
// affected version, so 3.3.5 and 3.3.7 must NOT match.
func TestLookupVulnerabilitySemverRange(t *testing.T) {
	lib := newLibrary(t)
	hit, err := lib.LookupVulnerability("event-stream", "npm", "3.3.6")
	if err != nil {
		t.Fatal(err)
	}
	if len(hit.Matches) == 0 {
		t.Fatalf("expected exact-version hit for event-stream@3.3.6")
	}
	miss, err := lib.LookupVulnerability("event-stream", "npm", "3.3.5")
	if err != nil {
		t.Fatal(err)
	}
	if len(miss.Matches) != 0 {
		t.Errorf("expected no hit for event-stream@3.3.5; got %+v", miss.Matches)
	}
}

// TestSetAllowedRootsRejectsAllInvalidInput covers the regression
// surfaced in PR #17 review: a non-empty --allowed-roots input whose
// entries all trim to "" (e.g. " " or ",, ,") must fail loudly
// instead of silently producing an empty allow-list (which would
// then be interpreted by validateScanPath as "no restriction" and
// open the door to every path the process can stat).
func TestSetAllowedRootsRejectsAllInvalidInput(t *testing.T) {
	lib := newLibrary(t)
	cases := [][]string{
		{" "},
		{",", " ", "\t"},
		{""},
	}
	for _, c := range cases {
		if err := lib.SetAllowedRoots(c); err == nil {
			t.Errorf("SetAllowedRoots(%q) must fail; got nil", c)
		}
	}
	// Sanity: a real directory still works.
	if err := lib.SetAllowedRoots([]string{t.TempDir()}); err != nil {
		t.Errorf("SetAllowedRoots with a valid dir must succeed: %v", err)
	}
}

// TestScanSecretsSymlinkBypassDenied covers the regression surfaced
// in PR #17 review: a symlink planted inside an allowed root that
// targets a file OUTSIDE every allowed root must be rejected by
// validateScanPath. Before the fix this passed because the abs path
// was under the allow-list, so the OR short-circuited and the
// resolved (outside) target was never checked.
func TestScanSecretsSymlinkBypassDenied(t *testing.T) {
	lib := newLibrary(t)
	allowed := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(target, []byte("AKIA1234567890ABCDEF\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(allowed, "leak")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	if err := lib.SetAllowedRoots([]string{allowed}); err != nil {
		t.Fatalf("SetAllowedRoots: %v", err)
	}
	if _, err := lib.ScanSecrets("", link); err == nil {
		t.Fatal("scan_secrets must deny a symlink that escapes the allow-list")
	} else if !strings.Contains(err.Error(), "allowed root") {
		t.Errorf("expected allow-list error, got: %v", err)
	}
	// Sanity: a regular file inside the allowed root still works.
	plain := filepath.Join(allowed, "ok.txt")
	if err := os.WriteFile(plain, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.ScanSecrets("", plain); err != nil {
		t.Errorf("regular file inside allow-list should be accepted: %v", err)
	}
}

// TestLoadPopularPackagesDedupes covers the loader-side defence:
// even if the source JSON contains a duplicate, the cached list
// (and therefore CheckTyposquat's PotentialTyposquats output) must
// contain each name at most once.
func TestLoadPopularPackagesDedupes(t *testing.T) {
	lib := newLibrary(t)
	pkgs, err := lib.loadPopularPackages("npm")
	if err != nil {
		t.Fatalf("loadPopularPackages npm: %v", err)
	}
	seen := make(map[string]int)
	for _, p := range pkgs {
		seen[strings.ToLower(p)]++
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("popular-package %q appears %d times after dedup", name, n)
		}
	}
}

// TestSARIFOmitemptyZeroValues guards the JSON-tag fix: ruleIndex
// and byteOffset/byteLength are semantically distinct from "unset"
// even at zero, so they must appear literally in the marshalled
// SARIF document. Before the fix `omitempty` dropped them silently.
func TestSARIFOmitemptyZeroValues(t *testing.T) {
	res := &SARIFResult{
		RuleID:    "skills-mcp.malicious-package",
		RuleIndex: 0,
		Message:   SARIFMultiformat{Text: "hi"},
		Locations: []SARIFLocation{{
			PhysicalLocation: SARIFPhysicalLocation{
				ArtifactLocation: SARIFArtifactLocation{URI: "stdin://text"},
				Region:           &SARIFRegion{ByteOffset: 0, ByteLength: 0},
			},
		}},
	}
	body, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, k := range []string{`"ruleIndex":0`, `"byteOffset":0`, `"byteLength":0`} {
		if !strings.Contains(s, k) {
			t.Errorf("SARIF JSON missing %s; got %s", k, s)
		}
	}
}
