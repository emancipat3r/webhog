package renderer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/launcher"
)

// requireBrowser skips the test when no Chromium is installed locally. The
// headless tests never trigger rod's auto-download.
func requireBrowser(t *testing.T) {
	t.Helper()
	if _, found := launcher.LookPath(); !found {
		t.Skip("no Chromium found on PATH; skipping headless test")
	}
}

// botShieldServer simulates a bot-management front: any request whose
// User-Agent does not look like a real browser gets a 403, exactly as
// Cloudflare-class fingerprinting rejects Go's TLS stack. It records the
// number of requests per path so double-fetching is detectable.
type botShieldServer struct {
	*httptest.Server
	mu   sync.Mutex
	hits map[string]int
	uas  map[string][]string
}

func newBotShieldServer(t *testing.T) *botShieldServer {
	t.Helper()
	s := &botShieldServer{hits: map[string]int{}, uas: map[string][]string{}}
	mux := http.NewServeMux()
	record := func(r *http.Request) bool {
		s.mu.Lock()
		s.hits[r.URL.Path]++
		s.uas[r.URL.Path] = append(s.uas[r.URL.Path], r.UserAgent())
		s.mu.Unlock()
		return strings.Contains(r.UserAgent(), "Chrome")
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !record(r) {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		_, _ = w.Write([]byte(`<html><head><script src="/app.js"></script><script src="/denied.js"></script></head>
<body><script>var inline = "yes"; fetch("/api/config.json");</script></body></html>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		if !record(r) {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`var appKey = "AKIAIOSFODNN7EXAMPLE";`))
	})
	mux.HandleFunc("/denied.js", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`// denied: internal endpoint /internal/debug`))
	})
	mux.HandleFunc("/api/config.json", func(w http.ResponseWriter, r *http.Request) {
		if !record(r) {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiKey":"from-xhr"}`))
	})
	s.Server = httptest.NewServer(mux)
	return s
}

func (s *botShieldServer) blob(res *RenderResult, suffix string) *JSBlob {
	for i := range res.JSBlobs {
		if strings.HasSuffix(res.JSBlobs[i].Path, suffix) {
			return &res.JSBlobs[i]
		}
	}
	return nil
}

// TestHeadlessScriptsComeFromBrowser is the PRD's acceptance test for
// browser-fetched scripts: against a host that refuses non-browser clients,
// --headless must still return external script bodies, each fetched exactly
// once and only by the browser.
func TestHeadlessScriptsComeFromBrowser(t *testing.T) {
	requireBrowser(t)
	srv := newBotShieldServer(t)
	defer srv.Close()

	r := NewHeadlessRenderer(20*time.Second, HTTPConfig{})
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := r.Render(ctx, srv.URL+"/")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if res.Status != 200 {
		t.Errorf("main document status = %d, want 200", res.Status)
	}

	app := srv.blob(res, "/app.js")
	if app == nil {
		t.Fatalf("external /app.js not captured; blobs=%+v errors=%+v", res.JSBlobs, res.Errors)
	}
	if app.Source != "external" || app.Status != 200 || !strings.Contains(app.Body, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("app.js blob = %+v, want external/200 with body", *app)
	}

	// A refused script is kept (its body may leak) and flagged via Status.
	denied := srv.blob(res, "/denied.js")
	if denied == nil {
		t.Fatalf("refused /denied.js not captured; blobs=%+v", res.JSBlobs)
	}
	if denied.Status != 403 || !strings.Contains(denied.Body, "/internal/debug") {
		t.Errorf("denied.js blob = %+v, want status 403 with body", *denied)
	}
	if got := res.Refused(); got != 1 {
		t.Errorf("Refused() = %d, want 1 (denied.js)", got)
	}

	// Runtime fetch() responses are captured as network blobs.
	cfgBlob := srv.blob(res, "/api/config.json")
	if cfgBlob == nil {
		t.Fatalf("runtime fetch /api/config.json not captured; blobs=%+v", res.JSBlobs)
	}
	if cfgBlob.Source != "network" || !strings.Contains(cfgBlob.Body, "from-xhr") {
		t.Errorf("config.json blob = %+v, want network with body", *cfgBlob)
	}

	// Inline scripts still come from the DOM.
	if inline := srv.blob(res, "#inline-1"); inline == nil || !strings.Contains(inline.Body, "var inline") {
		t.Errorf("inline script missing or wrong: %+v", inline)
	}

	// Repeated headers arrive as separate values, not one "\n"-joined string.
	var setCookie []string
	for k, v := range res.Headers {
		if strings.EqualFold(k, "set-cookie") {
			setCookie = v
		}
	}
	if len(setCookie) != 2 || strings.Contains(setCookie[0], "\n") {
		t.Errorf("Set-Cookie = %q, want two separate values", setCookie)
	}

	// Every resource was requested exactly once, by the browser.
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, p := range []string{"/", "/app.js", "/denied.js", "/api/config.json"} {
		if srv.hits[p] != 1 {
			t.Errorf("%s requested %d times, want exactly 1 (no re-fetch)", p, srv.hits[p])
		}
		for _, ua := range srv.uas[p] {
			if !strings.Contains(ua, "Chrome") {
				t.Errorf("%s requested with non-browser User-Agent %q", p, ua)
			}
		}
	}
}

// TestHeadlessOneBrowserPerRenderer is the PRD's acceptance test for browser
// reuse: many pages across several sessions must start exactly one Chromium.
func TestHeadlessOneBrowserPerRenderer(t *testing.T) {
	requireBrowser(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script>document.cookie = "seen=1";</script></body></html>`))
	}))
	defer srv.Close()

	r := NewHeadlessRenderer(20*time.Second, HTTPConfig{})
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for i := 0; i < 3; i++ {
		s, err := r.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		for j := 0; j < 3; j++ {
			if _, err := s.Render(ctx, srv.URL+"/"); err != nil {
				t.Fatalf("session %d render %d: %v", i, j, err)
			}
		}
		if err := s.Close(); err != nil {
			t.Errorf("session close: %v", err)
		}
	}
	if r.launches != 1 {
		t.Errorf("browser launched %d times for 9 pages across 3 sessions, want 1", r.launches)
	}
}

// TestHeadlessSessionsAreIsolated verifies that a cookie set while rendering
// in one session is not sent by a page in another session.
func TestHeadlessSessionsAreIsolated(t *testing.T) {
	requireBrowser(t)
	var mu sync.Mutex
	var cookies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cookies = append(cookies, r.Header.Get("Cookie"))
		mu.Unlock()
		w.Header().Set("Set-Cookie", "sess=abc; Path=/")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>ok</body></html>`))
	}))
	defer srv.Close()

	r := NewHeadlessRenderer(20*time.Second, HTTPConfig{})
	defer r.Close()
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		s, err := r.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		if _, err := s.Render(ctx, srv.URL+"/"); err != nil {
			t.Fatalf("render: %v", err)
		}
		_ = s.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(cookies))
	}
	for i, c := range cookies {
		if c != "" {
			t.Errorf("request %d carried cookie %q from another session; sessions must be isolated", i, c)
		}
	}
}

func TestSplitHeaderValues(t *testing.T) {
	cases := map[string][]string{
		"a=1":                      {"a=1"},
		"a=1\nb=2":                 {"a=1", "b=2"},
		"a=1\n\nb=2\n":             {"a=1", "b=2"},
		"text/html; charset=utf-8": {"text/html; charset=utf-8"},
	}
	for in, want := range cases {
		got := splitHeaderValues(in)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("splitHeaderValues(%q) = %q, want %q", in, got, want)
		}
	}
}
