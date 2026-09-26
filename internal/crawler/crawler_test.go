package crawler

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emancipat3r/webhog/internal/renderer"
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

// slowRenderer serves a wide, flat site where every page takes `delay` to
// render, so the wall time of a crawl reveals how many pages ran at once.
type slowRenderer struct {
	delay time.Duration
	width int
	mu    sync.Mutex
	inUse int
	peak  int
}

func (s *slowRenderer) Render(ctx context.Context, u string) (*renderer.RenderResult, error) {
	s.mu.Lock()
	s.inUse++
	if s.inUse > s.peak {
		s.peak = s.inUse
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inUse--
		s.mu.Unlock()
	}()

	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	html := ""
	if u == "http://example.test/" {
		var b strings.Builder
		for i := 0; i < s.width; i++ {
			fmt.Fprintf(&b, `<a href="/p%d">x</a>`, i)
		}
		html = b.String()
	}
	return &renderer.RenderResult{URL: u, Status: 200, HTML: html}, nil
}

// TestCrawlConcurrencySpeedsUp is the PRD's acceptance test for concurrency:
// a 40-page crawl at --concurrency 4 should take roughly a quarter of the
// serial wall time, and never run more than 4 renders at once.
func TestCrawlConcurrencySpeedsUp(t *testing.T) {
	const pages, delay = 40, 20 * time.Millisecond

	run := func(conc int) (time.Duration, int, int) {
		r := &slowRenderer{delay: delay, width: pages - 1}
		c := New(r, 1, 0, true, time.Second, nil).SetConcurrency(conc)
		start := time.Now()
		n := len(collect(c, "http://example.test/"))
		return time.Since(start), n, r.peak
	}

	serial, n1, peak1 := run(1)
	if n1 != pages || peak1 != 1 {
		t.Fatalf("serial: crawled %d pages (want %d) with peak concurrency %d (want 1)", n1, pages, peak1)
	}
	parallel, n4, peak4 := run(4)
	if n4 != pages {
		t.Fatalf("concurrency 4: crawled %d pages, want %d", n4, pages)
	}
	if peak4 > 4 {
		t.Errorf("concurrency 4: peak in-flight renders = %d, want <= 4", peak4)
	}
	if peak4 < 2 {
		t.Errorf("concurrency 4: peak in-flight renders = %d, workers never overlapped", peak4)
	}
	// Serial: 40 * 20ms = 800ms. Parallel: ~1 + 39/4 rounds ≈ 220ms.
	if parallel > serial/2 {
		t.Errorf("concurrency 4 took %v vs serial %v; expected a large speedup", parallel, serial)
	}
}

// TestCrawlMaxPagesIsExactUnderConcurrency checks that racing workers cannot
// overshoot the page cap.
func TestCrawlMaxPagesIsExactUnderConcurrency(t *testing.T) {
	r := &slowRenderer{delay: time.Millisecond, width: 100}
	c := New(r, 1, 7, true, time.Second, nil).SetConcurrency(8)
	if n := len(collect(c, "http://example.test/")); n != 7 {
		t.Errorf("maxPages=7 with 8 workers: rendered %d pages", n)
	}
}

// TestCrawlCancellationStopsWorkers verifies that cancelling the context ends
// the crawl promptly and closes the output channel.
func TestCrawlCancellationStopsWorkers(t *testing.T) {
	r := &slowRenderer{delay: 50 * time.Millisecond, width: 100}
	c := New(r, 1, 0, true, time.Second, nil).SetConcurrency(4)
	ctx, cancel := context.WithCancel(context.Background())

	pages := c.Crawl(ctx, "http://example.test/")
	<-pages // seed rendered
	cancel()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-pages:
			if !ok {
				return // channel closed: crawl ended
			}
		case <-deadline:
			t.Fatal("crawl did not end after cancellation")
		}
	}
}

// TestCrawlRedirectOffDomainDoesNotCrawlLanding is the fixture from the
// surfacer scope report: a seed that redirects to a different registrable
// domain whose landing page carries links. Fetching the seed through the
// redirect is in scope; crawling what it lands on is not. Exactly one page
// may be fetched and no landing-page link may be enqueued.
func TestCrawlRedirectOffDomainDoesNotCrawlLanding(t *testing.T) {
	var landing strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&landing, `<a href="/l%d">x</a><a href="https://other.test/abs%d">y</a>`, i, i)
	}
	pages := map[string]string{"https://other.test/landing": landing.String()}
	for i := 0; i < 10; i++ {
		pages[fmt.Sprintf("https://other.test/l%d", i)] = "leaf"
		pages[fmt.Sprintf("https://other.test/abs%d", i)] = "leaf"
	}
	fake := &fakeRenderer{
		redirects: map[string]string{"https://seed.test/": "https://other.test/landing"},
		pages:     pages,
	}
	// Endpoints "found" in the landing page text, including in-scope ones such
	// as the continue= URLs an SSO login page carries for the app behind it.
	// The landing page is out of scope, so even those must not be followed.
	extra := func(res *renderer.RenderResult) []string {
		return []string{"/api/from-js", "https://other.test/js-abs", "https://seed.test/continue", "https://app.seed.test/"}
	}
	pages["https://seed.test/continue"] = "leaf"
	pages["https://app.seed.test/"] = "leaf"
	c := New(fake, 3, 0, true, time.Second, extra).SetConcurrency(4)
	got := collect(c, "https://seed.test/")
	if len(got) != 1 || got[0] != "https://other.test/landing" {
		t.Fatalf("expected exactly the landing page, got %v", got)
	}
	if len(fake.requested) != 1 {
		t.Errorf("requested %d URLs, want 1 (seed only): %v", len(fake.requested), fake.requested)
	}
}
