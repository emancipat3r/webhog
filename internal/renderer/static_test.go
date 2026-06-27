package renderer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestStaticRendererAppliesHTTPConfig verifies that a custom User-Agent and
// extra header reach BOTH the top-level page request and the request for a
// referenced external .js file — the non-browser path the feature requires.
func TestStaticRendererAppliesHTTPConfig(t *testing.T) {
	const (
		wantUA     = "Mozilla/5.0 HackerOne myhandle"
		wantHeader = "myhandle"
	)

	var mu sync.Mutex
	seenUA := map[string]string{}
	seenResearch := map[string]string{}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenUA[r.URL.Path] = r.Header.Get("User-Agent")
		seenResearch[r.URL.Path] = r.Header.Get("X-HackerOne-Research")
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script src="/app.js"></script></body></html>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenUA[r.URL.Path] = r.Header.Get("User-Agent")
		seenResearch[r.URL.Path] = r.Header.Get("X-HackerOne-Research")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`var x = 1;`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := NewStaticRenderer(5*time.Second, HTTPConfig{
		UserAgent: wantUA,
		Headers:   []Header{{Key: "X-HackerOne-Research", Value: wantHeader}},
	})
	if _, err := r.Render(context.Background(), srv.URL+"/"); err != nil {
		t.Fatalf("Render: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/", "/app.js"} {
		if seenUA[path] != wantUA {
			t.Errorf("%s: User-Agent = %q, want %q", path, seenUA[path], wantUA)
		}
		if seenResearch[path] != wantHeader {
			t.Errorf("%s: X-HackerOne-Research = %q, want %q", path, seenResearch[path], wantHeader)
		}
	}
}

// TestStaticRendererDefaultUserAgent confirms the unset case keeps the existing
// default User-Agent (no behavior change when the flags are absent).
func TestStaticRendererDefaultUserAgent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	r := NewStaticRenderer(5*time.Second, HTTPConfig{})
	if _, err := r.Render(context.Background(), srv.URL+"/"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got != defaultUserAgent {
		t.Errorf("User-Agent = %q, want default %q", got, defaultUserAgent)
	}
}
