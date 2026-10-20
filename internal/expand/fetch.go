// Package expand widens what a rendered page exposes before it is scanned:
// the source maps its scripts point at, and the lazily loaded chunks a
// bundler only fetches when a route is visited. Every request it makes goes
// through the same identity and pacing as the renderer's.
package expand

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/emancipat3r/webhog/internal/renderer"
)

// DefaultMaxMapBytes caps a source map download. Maps for large single-page
// apps run to tens of megabytes; beyond this they are truncated and then
// fail to parse, which is reported as not exposed rather than as a crash.
const DefaultMaxMapBytes = 64 << 20

// DefaultMaxChunks caps how many chunks are fetched for one target.
const DefaultMaxChunks = 200

// Fetcher performs the expansion requests. It is shared across targets; the
// per-target state lives in Expander.
type Fetcher struct {
	client   *http.Client
	cfg      renderer.HTTPConfig
	maxBytes int64
}

// NewFetcher returns a Fetcher with the given timeout, identity and body cap.
func NewFetcher(timeout time.Duration, cfg renderer.HTTPConfig, maxBytes int64) *Fetcher {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxMapBytes
	}
	return &Fetcher{client: &http.Client{Timeout: timeout}, cfg: cfg, maxBytes: maxBytes}
}

// get fetches one URL, paced by the shared limiter, and returns the body
// (truncated at maxBytes) and status. A transport failure is an error.
func (f *Fetcher) get(ctx context.Context, u string, limit int64) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", renderer.DefaultUserAgent())
	f.cfg.Apply(req)
	if err := f.cfg.Wait(ctx); err != nil {
		return "", 0, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if limit <= 0 {
		limit = f.maxBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return "", resp.StatusCode, err
	}
	if int64(len(body)) > limit {
		return string(body[:limit]), resp.StatusCode, fmt.Errorf("body exceeds %d bytes", limit)
	}
	return string(body), resp.StatusCode, nil
}

// resolve returns ref made absolute against base, or "" when either does
// not parse or the result is not http(s).
func resolve(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return ""
	}
	abs := b.ResolveReference(r)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	abs.Fragment = ""
	return abs.String()
}

// isScriptPath reports whether a URL's path names a JavaScript file.
func isScriptPath(u string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	lower := strings.ToLower(p.Path)
	return strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs") || strings.HasSuffix(lower, ".cjs")
}
