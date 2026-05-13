package updater

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPSourceBearerAuth(t *testing.T) {
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"version":"1","generated":"2026-05-13T00:00:00Z","files":[]}`)
	}))
	t.Cleanup(srv.Close)

	src, err := NewHTTPSourceWithAuth(srv.URL, "tok-12345")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Manifest(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(seenAuth, "Bearer ") {
		t.Errorf("expected Bearer auth, got %q", seenAuth)
	}
	if !strings.HasSuffix(seenAuth, "tok-12345") {
		t.Errorf("expected token in auth, got %q", seenAuth)
	}
}

func TestHTTPSourceReturnsAuthErrorOn401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	src, err := NewHTTPSourceWithAuth(srv.URL, "bad")
	if err != nil {
		t.Fatal(err)
	}
	_, err = src.Manifest()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("expected authentication failure message, got %v", err)
	}
}

func TestHTTPSourceNoAuthHeaderWhenEmptyToken(t *testing.T) {
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"version":"1","generated":"2026-05-13T00:00:00Z","files":[]}`)
	}))
	t.Cleanup(srv.Close)

	src, err := NewHTTPSource(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Manifest(); err != nil {
		t.Fatal(err)
	}
	if seenAuth != "" {
		t.Errorf("expected no auth header, got %q", seenAuth)
	}
}
