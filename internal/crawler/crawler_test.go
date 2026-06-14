package crawler

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/user/webhog/internal/renderer"
)

// fakeRenderer serves canned HTML keyed by final URL, with no network access.
// It can simulate redirects (requested URL -> final URL) and records every
// URL it was asked to render.
type fakeRenderer struct {
	pages     map[string]string // final URL -> HTML
	redirects map[string]string // requested URL -> final URL
	requested []string
}

func (f *fakeRenderer) Render(_ context.Context, u string) (*renderer.RenderResult, error) {
	f.requested = append(f.requested, u)
	final := u
	if r, ok := f.redirects[u]; ok {
		final = r
	}
	html, ok := f.pages[final]
	if !ok {
		return nil, fmt.Errorf("not found: %s", final)
	}
	return &renderer.RenderResult{URL: final, Status: 200, HTML: html}, nil
}

func collect(c *Crawler, seed string) []string {
	var urls []string
	for p := range c.Crawl(context.Background(), seed) {
		if p.Err == nil {
			urls = append(urls, p.Result.URL)
		}
	}
	sort.Strings(urls)
	return urls
}

func newFake() *fakeRenderer {
	return &fakeRenderer{pages: map[string]string{
		"http://example.test/":  `<a href="/a">a</a><a href="/b">b</a><a href="https://other.test/x">ext</a>`,
		"http://example.test/a": `<a href="/c">c</a><a href="/a">self</a>`,
		"http://example.test/b": `no links`,
		"http://example.test/c": `leaf`,
		"https://other.test/x":  `external leaf`,
	}}
}

func TestCrawlDepthLimit(t *testing.T) {
	c := New(newFake(), 1, 0, true, time.Second, nil)
	got := collect(c, "http://example.test/")
	want := []string{"http://example.test/", "http://example.test/a", "http://example.test/b"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("depth 1: got %v, want %v", got, want)
	}
}

func TestCrawlReachesDeeperWithMoreDepth(t *testing.T) {
	c := New(newFake(), 2, 0, true, time.Second, nil)
	got := collect(c, "http://example.test/")
	want := []string{
		"http://example.test/", "http://example.test/a",
		"http://example.test/b", "http://example.test/c",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("depth 2: got %v, want %v", got, want)
	}
}

func TestCrawlSameDomainFilter(t *testing.T) {
	// With sameDomain disabled, the external host is followed.
	c := New(newFake(), 2, 0, false, time.Second, nil)
	found := false
	for _, u := range collect(c, "http://example.test/") {
		if u == "https://other.test/x" {
			found = true
		}
	}
	if !found {
		t.Error("expected external host to be crawled with sameDomain=false")
	}

	// With sameDomain enabled, it must be excluded.
	c = New(newFake(), 2, 0, true, time.Second, nil)
	for _, u := range collect(c, "http://example.test/") {
		if u == "https://other.test/x" {
			t.Errorf("external host should be excluded with sameDomain=true; got %v", u)
		}
	}
}

func TestCrawlMaxPages(t *testing.T) {
	c := New(newFake(), 5, 2, true, time.Second, nil)
	got := collect(c, "http://example.test/")
	if len(got) != 2 {
		t.Errorf("maxPages=2: expected 2 pages, got %d (%v)", len(got), got)
	}
}

func TestCrawlSkipsAssetsAndSchemes(t *testing.T) {
	fake := &fakeRenderer{pages: map[string]string{
		"http://example.test/": `
			<a href="/logo.png">asset</a>
			<a href="mailto:a@b.com">mail</a>
			<a href="/real">page</a>`,
		"http://example.test/real": `leaf`,
	}}
	c := New(fake, 1, 0, true, time.Second, nil)
	got := collect(c, "http://example.test/")
	want := []string{"http://example.test/", "http://example.test/real"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("asset/scheme filter: got %v, want %v", got, want)
	}
}

// TestCrawlFollowsExtraLinks verifies that URLs supplied by the extraLinks
// callback (e.g. endpoints discovered in JS) are crawled alongside anchors.
func TestCrawlFollowsExtraLinks(t *testing.T) {
	fake := &fakeRenderer{pages: map[string]string{
		"http://example.test/":           `<a href="/a">a</a>`,
		"http://example.test/a":          `leaf`,
		"http://example.test/api/secret": `{"k":"v"}`,
	}}
	extra := func(res *renderer.RenderResult) []string {
		if res.URL == "http://example.test/" {
			return []string{"/api/secret"} // discovered in JS, not an anchor
		}
		return nil
	}
	c := New(fake, 1, 0, true, time.Second, extra)
	got := collect(c, "http://example.test/")
	want := []string{
		"http://example.test/", "http://example.test/a", "http://example.test/api/secret",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("extra links: got %v, want %v", got, want)
	}
}

// TestCrawlMarksFinalURLVisited verifies that a redirect's target is recorded
// as visited, so discovering a link to it later does not trigger a re-fetch.
func TestCrawlMarksFinalURLVisited(t *testing.T) {
	fake := &fakeRenderer{
		redirects: map[string]string{
			"http://example.test/x": "http://example.test/landing",
		},
		pages: map[string]string{
			"http://example.test/":        `<a href="/x">x</a>`,
			"http://example.test/landing": `<a href="/more">more</a>`,
			"http://example.test/more":    `<a href="/landing">back</a>`,
		},
	}
	c := New(fake, 5, 0, true, time.Second, nil)
	_ = collect(c, "http://example.test/")

	for _, u := range fake.requested {
		if u == "http://example.test/landing" {
			t.Errorf("redirect target /landing should not be fetched directly; requested=%v", fake.requested)
		}
	}
	// Sanity: the crawl still reached /more through the redirect.
	reachedMore := false
	for _, u := range fake.requested {
		if u == "http://example.test/more" {
			reachedMore = true
		}
	}
	if !reachedMore {
		t.Errorf("expected crawl to reach /more; requested=%v", fake.requested)
	}
}

func TestSameRegisteredDomain(t *testing.T) {
	seed := registeredDomain("https://www.example.com/")
	if !sameRegisteredDomain(seed, "https://api.example.com/v1") {
		t.Error("api.example.com should share the registered domain of www.example.com")
	}
	if sameRegisteredDomain(seed, "https://evil.com/") {
		t.Error("evil.com should not share example.com's registered domain")
	}
}
