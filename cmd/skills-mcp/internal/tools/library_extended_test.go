package tools

import (
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
