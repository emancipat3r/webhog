package renderer

import (
	"net/http"
	"testing"
)

func TestHTTPConfigApply(t *testing.T) {
	t.Run("empty config leaves request untouched", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("User-Agent", defaultUserAgent)
		HTTPConfig{}.Apply(req)
		if got := req.Header.Get("User-Agent"); got != defaultUserAgent {
			t.Errorf("User-Agent = %q, want default %q", got, defaultUserAgent)
		}
	})

	t.Run("overrides user-agent and adds headers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("User-Agent", defaultUserAgent)
		cfg := HTTPConfig{
			UserAgent: "Mozilla/5.0 HackerOne myhandle",
			Headers:   []Header{{Key: "X-HackerOne-Research", Value: "myhandle"}},
		}
		cfg.Apply(req)
		if got := req.Header.Get("User-Agent"); got != cfg.UserAgent {
			t.Errorf("User-Agent = %q, want %q", got, cfg.UserAgent)
		}
		if got := req.Header.Get("X-HackerOne-Research"); got != "myhandle" {
			t.Errorf("X-HackerOne-Research = %q, want %q", got, "myhandle")
		}
	})

	t.Run("does not override reserved Host header", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		cfg := HTTPConfig{Headers: []Header{{Key: "Host", Value: "evil.example"}}}
		cfg.Apply(req)
		if got := req.Header.Get("Host"); got != "" {
			t.Errorf("Host header = %q, want it left unset", got)
		}
	})
}

func TestHTTPConfigHeaderPairs(t *testing.T) {
	cfg := HTTPConfig{Headers: []Header{
		{Key: "X-HackerOne-Research", Value: "myhandle"},
		{Key: "Host", Value: "evil.example"}, // reserved, must be dropped
		{Key: "X-Extra", Value: "1"},
	}}
	got := cfg.HeaderPairs()
	want := []string{"X-HackerOne-Research", "myhandle", "X-Extra", "1"}
	if len(got) != len(want) {
		t.Fatalf("HeaderPairs() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("HeaderPairs()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
