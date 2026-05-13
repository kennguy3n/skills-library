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

// TestConfigureClearRecoversFromCorruptedConfig verifies that --clear can
// recover from a malformed .skills-check.yaml. Without the fix, LoadConfig
// returns an error before clearAll is honored, so the documented reset
// workflow is unreachable in exactly the situation it is meant to handle.
func TestConfigureClearRecoversFromCorruptedConfig(t *testing.T) {
	t.Run("malformed yaml", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, ".skills-check.yaml")
		if err := os.WriteFile(path, []byte("schema_version: \"1.0\"\nsource: [unterminated\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executeRoot(t, "configure", "--dir", tmp, "--clear"); err != nil {
			t.Fatalf("--clear should recover from malformed yaml, got: %v", err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got := string(body)
		if !strings.Contains(got, "schema_version: \"1.0\"") {
			t.Errorf("expected reset config, got:\n%s", got)
		}
		if strings.Contains(got, "[unterminated") {
			t.Errorf("expected corrupt content to be overwritten, got:\n%s", got)
		}
	})

	t.Run("missing schema_version", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, ".skills-check.yaml")
		if err := os.WriteFile(path, []byte("source: https://stale.example.com\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executeRoot(t, "configure", "--dir", tmp, "--clear"); err != nil {
			t.Fatalf("--clear should recover from missing schema_version, got: %v", err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got := string(body)
		if !strings.Contains(got, "schema_version: \"1.0\"") {
			t.Errorf("expected reset config, got:\n%s", got)
		}
		if strings.Contains(got, "stale.example.com") {
			t.Errorf("expected stale source to be overwritten, got:\n%s", got)
		}
	})

	t.Run("clear plus new source in one invocation", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, ".skills-check.yaml")
		if err := os.WriteFile(path, []byte("source: [malformed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executeRoot(t,
			"configure", "--dir", tmp, "--clear",
			"--source", "https://fresh.example.com",
		); err != nil {
			t.Fatalf("--clear with new flags should succeed, got: %v", err)
		}
		body, _ := os.ReadFile(path)
		got := string(body)
		if !strings.Contains(got, "source: https://fresh.example.com") {
			t.Errorf("expected new source applied after clear, got:\n%s", got)
		}
	})

	t.Run("missing file still works without --clear", func(t *testing.T) {
		tmp := t.TempDir()
		if _, _, err := executeRoot(t,
			"configure", "--dir", tmp, "--source", "https://a/",
		); err != nil {
			t.Fatalf("missing config should not require --clear, got: %v", err)
		}
	})

	t.Run("corrupt config without --clear still errors", func(t *testing.T) {
		tmp := t.TempDir()
		if err := os.WriteFile(filepath.Join(tmp, ".skills-check.yaml"), []byte("source: [unterminated\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executeRoot(t,
			"configure", "--dir", tmp, "--source", "https://b/",
		); err == nil {
			t.Errorf("expected error when running configure against corrupt config without --clear")
		}
	})
}
