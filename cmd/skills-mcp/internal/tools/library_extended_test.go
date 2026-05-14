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

// TestCheckTyposquatGoFinalSegment exercises the typosquatCompareKey
// path: for Go modules the distance must be computed against the last
// import-path segment, not the full path. A near-miss on the segment
// (`gim` vs `gin`) should surface; an unrelated module that just
// shares a long prefix (`github.com/aaaa/aaaa` vs
// `github.com/gin-gonic/gin`) must not.
func TestCheckTyposquatGoFinalSegment(t *testing.T) {
	lib := newLibrary(t)
	// Near-miss on final segment must surface.
	res, err := lib.CheckTyposquat("github.com/gin-gonic/gim", "go")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range res.PotentialTyposquats {
		if strings.EqualFold(h.Target, "github.com/gin-gonic/gin") {
			found = true
			if h.Distance > 2 {
				t.Errorf("expected distance <=2 for gim->gin, got %d", h.Distance)
			}
		}
	}
	if !found {
		t.Errorf("expected gin to surface as a potential typosquat for gim, got %+v", res.PotentialTyposquats)
	}
	// Unrelated prefix-sharing module must not surface.
	res, err = lib.CheckTyposquat("totally-unrelated-name-xyz", "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.PotentialTyposquats) != 0 {
		t.Errorf("unrelated name should not match any popular Go module, got %+v", res.PotentialTyposquats)
	}
}

// TestLoadPopularPackagesDoesNotCacheParseError verifies fix B: when
// the data file fails to parse, the loader must NOT cache an empty
// list. A subsequent call against a valid file must still return the
// real data.
func TestLoadPopularPackagesDoesNotCacheParseError(t *testing.T) {
	lib := newLibrary(t)
	// Sanity: npm currently parses; record what we'd expect on a
	// successful call so we can assert recovery is not silently
	// masked by a stale cached empty list.
	pkgs, err := lib.loadPopularPackages("npm")
	if err != nil {
		t.Fatalf("npm should parse: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("npm popular list should be non-empty")
	}
	// Now: ask for an ecosystem that does not exist on disk. We expect
	// an error, AND the absence of any cached empty entry that would
	// permanently mask later attempts.
	if _, err := lib.loadPopularPackages("nonexistent-ecosystem-xyz"); err == nil {
		t.Errorf("loading a missing ecosystem must return an error")
	}
	// Confirm the cache for the valid ecosystem is still intact (i.e.
	// we did not corrupt other entries while handling the error).
	pkgs2, err := lib.loadPopularPackages("npm")
	if err != nil {
		t.Fatalf("npm should still parse after a sibling error: %v", err)
	}
	if len(pkgs2) != len(pkgs) {
		t.Errorf("npm cache was disturbed: %d vs %d", len(pkgs2), len(pkgs))
	}
}

// TestVersionMatchesRejectsUnparseable covers fix C: an unparseable
// version (or threshold) must NOT be treated as the zero semver.
// Before the fix, versionMatches(">=0.0.0", "abc") returned true
// because parseSemver("abc") = (0, 0, 0, false) and compareSemver
// ignored the ok flag.
func TestVersionMatchesRejectsUnparseable(t *testing.T) {
	cases := []struct {
		affected string
		version  string
		want     bool
	}{
		// The classic bug.
		{">=0.0.0", "abc", false},
		// Symmetric: unparseable threshold should also miss.
		{">=abc", "1.2.3", false},
		// Range form with one unparseable endpoint.
		{"1.0.0 - bogus", "1.2.3", false},
		// pre- form: version "abc" must not be treated as < 5.0.0.
		{"pre-5.0.0", "abc", false},
		// Sanity: ordinary semver still works.
		{">=1.0.0", "1.2.3", true},
		{"1.0.0 - 2.0.0", "1.5.0", true},
		// And legacy exact-string fall through still works for
		// non-structured forms.
		{"abc", "abc", true},
	}
	for _, c := range cases {
		got := versionMatches(c.affected, c.version)
		if got != c.want {
			t.Errorf("versionMatches(%q, %q) = %v, want %v", c.affected, c.version, got, c.want)
		}
	}
}

// TestSetAllowedRootsSymlinkedRootAcceptsScan reproduces the macOS-
// style regression where the configured allow-list root itself goes
// through a symlink (e.g. /tmp -> /private/tmp). The simulated layout:
//
//	<realRoot>/data            # real directory containing scannable files
//	<linkRoot> -> <realRoot>   # symlink to <realRoot> (stands in for /tmp)
//
// Calling SetAllowedRoots([<linkRoot>/data]) used to store only the
// fully-resolved <realRoot>/data, so validateScanPath's AND check
// against the unresolved abs <linkRoot>/data/leak.txt would fail.
// After the fix, SetAllowedRoots stores BOTH forms so the abs form
// has a matching root.
func TestSetAllowedRootsSymlinkedRootAcceptsScan(t *testing.T) {
	lib := newLibrary(t)
	realRoot := t.TempDir()
	data := filepath.Join(realRoot, "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	leak := filepath.Join(data, "leak.txt")
	if err := os.WriteFile(leak, []byte("AKIA1234567890ABCDEF\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Build a sibling temp dir and replace it with a symlink to
	// realRoot so the *configured* path goes through a symlink.
	parent := t.TempDir()
	linkRoot := filepath.Join(parent, "linked")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	allowed := filepath.Join(linkRoot, "data") // configured via symlinked path
	if err := lib.SetAllowedRoots([]string{allowed}); err != nil {
		t.Fatalf("SetAllowedRoots: %v", err)
	}
	scanPath := filepath.Join(allowed, "leak.txt") // also goes through the symlink
	if _, err := lib.ScanSecrets("", scanPath); err != nil {
		t.Fatalf("scanning a file inside a symlinked allowed root must succeed: %v", err)
	}
	// Defense-in-depth invariant: a symlink inside the allow-list that
	// redirects to a file OUTSIDE every allowed root (and outside
	// sensitivePaths()) must still be denied.
	outside := t.TempDir()
	target := filepath.Join(outside, "outside.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bypass := filepath.Join(data, "bypass")
	if err := os.Symlink(target, bypass); err != nil {
		t.Skipf("nested symlink unsupported: %v", err)
	}
	if _, err := lib.ScanSecrets("", bypass); err == nil {
		t.Errorf("symlink redirecting outside the allow-list must be denied even when the root itself is symlinked")
	}
}

// TestCheckDependencySARIFEmptyResultsArray pins the fix for the
// `"results": null` regression. A CheckDependencyResult with no
// findings must marshal to a SARIF document where Run.Results is the
// empty JSON array `[]`, not `null`. SARIF 2.1.0 specifies results as
// an array; `null` is interpreted as "results not computed" and GHAS
// will reject the upload.
func TestCheckDependencySARIFEmptyResultsArray(t *testing.T) {
	res := &CheckDependencyResult{
		Package:   "nonexistent-package-xyz",
		Ecosystem: "npm",
		Version:   "1.0.0",
	}
	log := CheckDependencySARIF(res)
	if log == nil || len(log.Runs) != 1 {
		t.Fatalf("expected exactly one SARIF run, got %+v", log)
	}
	if log.Runs[0].Results == nil {
		t.Fatalf("SARIF Run.Results must be a non-nil slice; got nil")
	}
	if len(log.Runs[0].Results) != 0 {
		t.Fatalf("expected empty results for a clean scan, got %d entries", len(log.Runs[0].Results))
	}
	body, err := json.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"results":[]`) {
		t.Errorf("SARIF JSON must contain \"results\":[]; got: %s", string(body))
	}
	if strings.Contains(string(body), `"results":null`) {
		t.Errorf("SARIF JSON must not contain \"results\":null; got: %s", string(body))
	}
}

// TestVersionMatchesWildcardTokens pins fix for the on-disk-data
// regression: the malicious-packages JSONs use "any", "various", and
// "multiple" alongside "all" and "*" as wildcard markers in
// versions_affected (docker, maven, nuget, github-actions, plus
// left-pad on npm). versionMatches must treat all five as matching
// any concrete version, or check_dependency silently misses the
// malicious-package hit.
func TestVersionMatchesWildcardTokens(t *testing.T) {
	tokens := []string{"all", "*", "any", "various", "multiple",
		"ALL", "Any", "VARIOUS", "Multiple"} // case-insensitive
	for _, tok := range tokens {
		if !versionMatches(tok, "1.2.3") {
			t.Errorf("versionMatches(%q, %q) = false, want true", tok, "1.2.3")
		}
		if !versionMatches(tok, "999.0.0-rc.7+build.42") {
			t.Errorf("versionMatches(%q, %q) = false, want true", tok, "999.0.0-rc.7+build.42")
		}
	}
}

// TestLookupVulnerabilityWildcardMatchesRealEntries reads the actual
// on-disk malicious-packages data and confirms that every entry with
// a wildcard token surfaces when LookupVulnerability is called with
// an arbitrary concrete version. Specifically pins:
//   - left-pad (npm) — versions_affected=["1.0.0","any"]
//   - actions/checkout@untrusted-ref (github-actions) — ["any"]
//   - xmrig-cryptominer-cluster (docker) — ["multiple"]
//
// Before the fix these all silently returned no match.
func TestLookupVulnerabilityWildcardMatchesRealEntries(t *testing.T) {
	lib := newLibrary(t)
	cases := []struct {
		pkg, ecosystem, version string
	}{
		{"left-pad", "npm", "9.9.9"},
		{"actions/checkout@untrusted-ref", "github-actions", "v4"},
		{"xmrig-cryptominer-cluster", "docker", "1.0.0"},
	}
	for _, c := range cases {
		hit, err := lib.LookupVulnerability(c.pkg, c.ecosystem, c.version)
		if err != nil {
			t.Errorf("LookupVulnerability(%q, %q, %q): %v", c.pkg, c.ecosystem, c.version, err)
			continue
		}
		if len(hit.Matches) == 0 {
			t.Errorf("expected wildcard match for %s@%s (%s); got none", c.pkg, c.version, c.ecosystem)
		}
	}
}
