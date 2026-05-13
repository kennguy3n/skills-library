package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureWritesFile(t *testing.T) {
	tmp := t.TempDir()
	stdout, _, err := executeRoot(t,
		"configure",
		"--dir", tmp,
		"--source", "https://skills.internal.example.com",
		"--bearer-token-env", "MY_TOKEN",
		"--trusted-key", "/etc/skills/orgkey.pem",
		"--profile", "financial-services",
	)
	if err != nil {
		t.Fatalf("configure: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, ".skills-check.yaml") {
		t.Errorf("unexpected stdout: %s", stdout)
	}

	body, err := os.ReadFile(filepath.Join(tmp, ".skills-check.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	for _, want := range []string{
		"schema_version: \"1.0\"",
		"source: https://skills.internal.example.com",
		"bearer_token_env: MY_TOKEN",
		"orgkey.pem",
		"profile: financial-services",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in config, got:\n%s", want, got)
		}
	}
}

func TestLoadConfigMissing(t *testing.T) {
	tmp := t.TempDir()
	cfg, exists, err := LoadConfig(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("expected exists=false")
	}
	if cfg.SchemaVersion == "" {
		t.Error("expected default schema_version")
	}
}

func TestResolveBearerTokenFromEnv(t *testing.T) {
	t.Setenv("MY_TOKEN_ENV", "secret-token-value")
	cfg := &SkillsCheckConfig{BearerTokenEnv: "MY_TOKEN_ENV"}
	if got := cfg.ResolveBearerToken(); got != "secret-token-value" {
		t.Errorf("got %q", got)
	}
	cfg.BearerToken = "literal"
	if got := cfg.ResolveBearerToken(); got != "literal" {
		t.Errorf("literal should win, got %q", got)
	}
}

func TestConfigureClearAll(t *testing.T) {
	tmp := t.TempDir()
	if _, _, err := executeRoot(t,
		"configure", "--dir", tmp,
		"--source", "https://a/", "--profile", "p1",
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executeRoot(t,
		"configure", "--dir", tmp, "--clear",
	); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(filepath.Join(tmp, ".skills-check.yaml"))
	if strings.Contains(string(body), "profile: p1") {
		t.Errorf("expected profile cleared, got:\n%s", body)
	}
}
