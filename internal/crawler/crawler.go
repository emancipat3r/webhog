// Package crawler performs a breadth-first crawl of a website, rendering each
// reachable page so it can be scanned for secrets and endpoints.
package crawler

import (
	"context"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/user/webhog/internal/renderer"
)

// Page is the outcome of attempting to render one crawled URL.
type Page struct {
	URL    string                 // the URL that was requested
	Depth  int                    // crawl depth (0 = seed)
	Result *renderer.RenderResult // nil when Err != nil
	Err    error                  // non-nil if the page failed to render
}

// LinkFunc returns additional candidate URLs to crawl from a rendered page,
// beyond its <a href> anchors. It is used to feed URLs and endpoints discovered
// inside JavaScript/HTML back into the frontier. Returned values may be
// relative; the crawler resolves and scope-filters them.
type LinkFunc func(*renderer.RenderResult) []string

// Crawler walks a site breadth-first from a seed URL, rendering each page with
// the configured renderer.
type Crawler struct {
	renderer   renderer.Renderer
	maxDepth   int           // 0 = seed only
	maxPages   int           // 0 = unlimited
	sameDomain bool          // restrict to the seed's registered (apex) domain
	perPage    time.Duration // per-page render timeout
	extraLinks LinkFunc      // optional source of additional crawl targets
}

// New creates a Crawler. extraLinks may be nil, in which case only <a href>
// anchors are followed.
func New(r renderer.Renderer, maxDepth, maxPages int, sameDomain bool, perPage time.Duration, extraLinks LinkFunc) *Crawler {
	return &Crawler{
		renderer:   r,
		maxDepth:   maxDepth,
		maxPages:   maxPages,
		sameDomain: sameDomain,
		perPage:    perPage,
		extraLinks: extraLinks,
	}
}

// Crawl renders the given seeds and, up to maxDepth/maxPages, the pages
// reachable from them (via anchors and any extraLinks), emitting one Page per
// rendered URL on the returned channel in breadth-first order. All seeds start
// at depth 0; the first seed defines the registered-domain scope. Each render
// is bounded by its own perPage timeout. The channel is closed when the crawl
// finishes or ctx is cancelled.
func (c *Crawler) Crawl(ctx context.Context, seeds ...string) <-chan Page {
	out := make(chan Page)

	go func() {
		defer close(out)

		if len(seeds) == 0 {
			return
		}
		seedDomain := registeredDomain(seeds[0])

		type item struct {
			url   string
			depth int
		}

		var queue []item
		visited := make(map[string]bool)
		for _, s := range seeds {
			n := normalizeURL(s)
			if !visited[n] {
				visited[n] = true
				queue = append(queue, item{url: n, depth: 0})
			}
		}
		pages := 0

		for len(queue) > 0 {
			if c.maxPages > 0 && pages >= c.maxPages {
				return
			}

			cur := queue[0]
			queue = queue[1:]

			select {
			case <-ctx.Done():
				return
			default:
			}

			pctx, cancel := context.WithTimeout(ctx, c.perPage)
			result, err := c.renderer.Render(pctx, cur.url)
			cancel()
			pages++

			select {
			case out <- Page{URL: cur.url, Depth: cur.depth, Result: result, Err: err}:
			case <-ctx.Done():
				return
			}

			if err != nil || result == nil {
				continue
			}

			// Mark the post-redirect URL visited too, so a redirect target
			// reached again (directly or via a link back) is not re-fetched.
			visited[normalizeURL(result.URL)] = true

			if cur.depth >= c.maxDepth {
				continue
			}

			for _, link := range c.candidates(result) {
				n, ok := c.inScope(seedDomain, result.URL, link)
				if !ok || visited[n] {
					continue
				}
				visited[n] = true
				queue = append(queue, item{url: n, depth: cur.depth + 1})
			}
		}
	}()

	return out
}

// candidates gathers the raw link candidates from a page: its anchors plus any
// extraLinks (e.g. endpoints discovered in JavaScript).
func (c *Crawler) candidates(result *renderer.RenderResult) []string {
	links := anchorHrefs(result.HTML)
	if c.extraLinks != nil {
		links = append(links, c.extraLinks(result)...)
	}
	return links
}

// inScope resolves a raw link against the page URL and decides whether it is a
// crawlable target. It returns the normalized absolute URL and true when the
// link is an http(s) URL, is not an obvious static asset, and (when sameDomain
// is set) shares the seed's registered domain.
func (c *Crawler) inScope(seedDomain, base, link string) (string, bool) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	ref, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return "", false
	}

	abs := baseURL.ResolveReference(ref)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return "", false
	}
	abs.Fragment = ""
	if skipExtensions[strings.ToLower(path.Ext(abs.Path))] {
		return "", false
	}

	n := normalizeURL(abs.String())
	if c.sameDomain && !sameRegisteredDomain(seedDomain, n) {
		return "", false
	}
	return n, true
}
