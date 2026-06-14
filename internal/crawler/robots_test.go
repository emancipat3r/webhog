package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"
)

func TestCleanRobotsPath(t *testing.T) {
	cases := map[string]string{
		"/admin/":      "/admin/",
		"/admin/*":     "/admin/",
		"/search?q=$":  "/search?q=",
		"/*.json":      "", // wildcard at the start leaves nothing useful
		"/":            "",
		"":             "",
		"relative":     "",
		"*":            "",
		"/internal/v2": "/internal/v2",
	}
	for in, want := range cases {
		if got := cleanRobotsPath(in); got != want {
			t.Errorf("cleanRobotsPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRobotsTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/robots.txt" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`# comment
User-agent: *
Disallow: /admin/
Disallow: /internal/*
Allow: /public
Disallow: /
Disallow:

Sitemap: ` + "SITEMAP_URL" + `
`))
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	got := RobotsTargets(context.Background(), srv.URL+"/", client)
	sort.Strings(got)

	want := []string{
		srv.URL + "/SITEMAP_URL", // resolved relative to origin
		srv.URL + "/admin/",
		srv.URL + "/internal/",
		srv.URL + "/public",
	}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRobotsTargetsAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	if got := RobotsTargets(context.Background(), srv.URL+"/", &http.Client{Timeout: 2 * time.Second}); got != nil {
		t.Errorf("expected nil for missing robots.txt, got %v", got)
	}
}
