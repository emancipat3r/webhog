package renderer

import (
	"context"
	"strings"
	"testing"
)

type fakeRenderer struct {
	results map[string]*RenderResult
	calls   []string
}

func (f *fakeRenderer) Render(_ context.Context, u string) (*RenderResult, error) {
	f.calls = append(f.calls, u)
	if r, ok := f.results[u]; ok {
		return r, nil
	}
	return &RenderResult{URL: u, Status: 200, HTML: "<html>fine</html>"}, nil
}

type fakeSessioner struct {
	r        *fakeRenderer
	sessions int
}

type fakeSession struct{ *fakeRenderer }

func (fakeSession) Close() error { return nil }

func (s *fakeSessioner) NewSession() (Session, error) {
	s.sessions++
	return fakeSession{s.r}, nil
}

func TestLooksBlocked(t *testing.T) {
	cases := []struct {
		name string
		res  *RenderResult
		want bool
	}{
		{"plain 200", &RenderResult{Status: 200, HTML: "<html>hello</html>"}, false},
		{"403 small body", &RenderResult{Status: 403, HTML: "<html>Forbidden</html>"}, true},
		{"cloudflare interstitial", &RenderResult{Status: 503, HTML: "<title>Just a moment...</title>"}, true},
		{"akamai reference", &RenderResult{Status: 403, HTML: strings.Repeat("x", 9000) + "errors.edgesuite.net"}, true},
		{"403 real page with scripts served", &RenderResult{Status: 403, HTML: strings.Repeat("x", 9000),
			JSBlobs: []JSBlob{{Source: "external", Path: "https://a/x.js", Status: 200}}}, false},
		{"403 every script refused", &RenderResult{Status: 403, HTML: strings.Repeat("x", 9000),
			JSBlobs: []JSBlob{{Source: "external", Path: "https://a/x.js", Status: 403}}}, true},
		{"200 with px marker", &RenderResult{Status: 200, HTML: "<script src='https://client.px-cdn.net/x'></script>"}, true},
	}
	for _, c := range cases {
		if got := LooksBlocked(c.res); got != c.want {
			t.Errorf("%s: LooksBlocked = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestAutoRendererSwitchesOnceForABlockedTarget: an unblocked target never
// touches the browser; a blocked one switches on the blocked page and
// stays switched for the rest of its pages.
func TestAutoRendererSwitchesOnceForABlockedTarget(t *testing.T) {
	static := &fakeRenderer{results: map[string]*RenderResult{
		"https://b.example/": {URL: "https://b.example/", Status: 403, HTML: "Just a moment..."},
	}}
	browser := &fakeRenderer{results: map[string]*RenderResult{
		"https://b.example/": {URL: "https://b.example/", Status: 200, HTML: "<html>rendered</html>"},
	}}
	hs := &fakeSessioner{r: browser}
	var switched []string
	a := NewAutoRenderer(static, hs, func(u string) { switched = append(switched, u) })

	s1, _ := a.NewSession()
	for _, u := range []string{"https://a.example/", "https://a.example/two"} {
		if res, err := s1.Render(context.Background(), u); err != nil || res.Status != 200 {
			t.Fatalf("%s: %v %+v", u, err, res)
		}
	}
	if hs.sessions != 0 || len(browser.calls) != 0 {
		t.Errorf("unblocked target reached the browser: sessions=%d calls=%v", hs.sessions, browser.calls)
	}

	s2, _ := a.NewSession()
	res, err := s2.Render(context.Background(), "https://b.example/")
	if err != nil || res.HTML != "<html>rendered</html>" {
		t.Fatalf("blocked seed: %v %+v", err, res)
	}
	if _, err := s2.Render(context.Background(), "https://b.example/next"); err != nil {
		t.Fatal(err)
	}
	if hs.sessions != 1 || len(switched) != 1 || switched[0] != "https://b.example/" {
		t.Errorf("sessions=%d switched=%v", hs.sessions, switched)
	}
	if len(browser.calls) != 2 || browser.calls[1] != "https://b.example/next" {
		t.Errorf("browser calls %v, want the seed and the next page", browser.calls)
	}
	if n := len(static.calls); n != 3 {
		t.Errorf("static calls %d, want 3 (two unblocked pages, one blocked seed)", n)
	}
	_ = s1.Close()
	_ = s2.Close()
}
