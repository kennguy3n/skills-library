package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	t.Fatalf("could not find repo root from %s", wd)
	return ""
}

func newServer(t *testing.T) *Server {
	t.Helper()
	srv, err := NewServer(repoRoot(t))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInitializeReturnsServerInfo(t *testing.T) {
	srv := newServer(t)
	req := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
	})
	resp := srv.HandleLine(req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected ok response, got %+v", resp)
	}
	result := resp.Result.(map[string]interface{})
	info := result["serverInfo"].(map[string]string)
	if info["name"] != "skills-mcp" {
		t.Errorf("serverInfo.name=%q", info["name"])
	}
}

func TestToolsListReturnsFourTools(t *testing.T) {
	srv := newServer(t)
	req := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	})
	resp := srv.HandleLine(req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected ok response, got %+v", resp)
	}
	result := resp.Result.(map[string]interface{})
	tools := result["tools"].([]map[string]interface{})
	if len(tools) != 4 {
		t.Fatalf("expected 4 tools, got %d", len(tools))
	}
	want := map[string]bool{
		"lookup_vulnerability": false,
		"check_secret_pattern": false,
		"get_skill":            false,
		"search_skills":        false,
	}
	for _, tdef := range tools {
		name := tdef["name"].(string)
		if _, ok := want[name]; !ok {
			t.Errorf("unexpected tool %q", name)
		}
		want[name] = true
		if _, ok := tdef["inputSchema"]; !ok {
			t.Errorf("tool %q has no inputSchema", name)
		}
	}
	for name, ok := range want {
		if !ok {
			t.Errorf("tool %q missing from tools/list", name)
		}
	}
}

func TestToolsCallLookupVulnerability(t *testing.T) {
	srv := newServer(t)
	req := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "lookup_vulnerability",
			"arguments": map[string]string{
				"package":   "event-stream",
				"ecosystem": "npm",
			},
		},
	})
	resp := srv.HandleLine(req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected ok response, got %+v", resp)
	}
	res := resp.Result.(map[string]interface{})
	body, _ := json.Marshal(res)
	if !strings.Contains(string(body), "event-stream") {
		t.Errorf("response did not contain event-stream; got %s", body)
	}
}

func TestToolsCallSearchSkills(t *testing.T) {
	srv := newServer(t)
	req := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "search_skills",
			"arguments": map[string]string{"query": "secret"},
		},
	})
	resp := srv.HandleLine(req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected ok response, got %+v", resp)
	}
	body, _ := json.Marshal(resp.Result)
	if !strings.Contains(string(body), "secret-detection") {
		t.Errorf("expected secret-detection in response, got %s", body)
	}
}

func TestUnknownMethodReturnsErr(t *testing.T) {
	srv := newServer(t)
	req := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      5,
		"method":  "bogus",
	})
	resp := srv.HandleLine(req)
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response; got %+v", resp)
	}
	if resp.Error.Code != codeMethodNotFound {
		t.Errorf("code=%d want %d", resp.Error.Code, codeMethodNotFound)
	}
}

func TestServeOverPipe(t *testing.T) {
	srv := newServer(t)
	in := bytes.NewBufferString(string(mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	})) + "\n")
	out := &bytes.Buffer{}
	if err := srv.Serve(in, out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if !strings.Contains(out.String(), "lookup_vulnerability") {
		t.Errorf("Serve output missing tool name: %s", out.String())
	}
}

func TestNotificationProducesNoResponse(t *testing.T) {
	srv := newServer(t)
	req := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "initialize",
	})
	if resp := srv.HandleLine(req); resp != nil {
		t.Errorf("notification should not produce a response; got %+v", resp)
	}
}
