package renderer

import (
	"context"
	"net/http"
	"strings"

	"github.com/emancipat3r/webhog/internal/ratelimit"
	"github.com/emancipat3r/webhog/internal/version"
)

// defaultUserAgent is the User-Agent webhog sends when the caller does not
// override it via --user-agent. It carries the build version.
var defaultUserAgent = version.UserAgent()

// Header is a single extra request header supplied by the caller.
type Header struct {
	Key   string
	Value string
}

// HTTPConfig carries request customizations that webhog applies to every
// outbound HTTP request it makes: the top-level page fetch, referenced
// sub-resource (JS) fetches, and the headless browser's main document and
// sub-resources. It exists so callers (e.g. bug-bounty programs that mandate an
// identifiable User-Agent or an X-HackerOne-Research header) can attribute all
// recon traffic. The zero value reproduces webhog's default, anonymous-ish
// behavior.
type HTTPConfig struct {
	// UserAgent overrides the default User-Agent on every request when non-empty.
	UserAgent string
	// Headers are extra request headers added to every request, applied in order.
	Headers []Header
	// Limiter paces every request webhog originates against the target: page
	// fetches, script fetches in static mode, robots.txt, and headless
	// navigations. nil means unlimited. Sub-resources the browser fetches on
	// its own during a navigation are outside its reach; one navigation
	// counts as one request.
	Limiter *ratelimit.Limiter
}

// Wait blocks until the limiter allows the next request (immediately when no
// limiter is configured). It returns ctx's error if ctx ends first.
func (c HTTPConfig) Wait(ctx context.Context) error {
	return c.Limiter.Wait(ctx)
}

// reservedHeader reports whether key names a request header that webhog manages
// itself and must not let a caller override, because correctness depends on it.
// Host is derived from the request URL (and relied on by the server and redirect
// handling); the User-Agent is intentionally NOT reserved — overriding it is the
// whole point of --user-agent.
func reservedHeader(key string) bool {
	return strings.EqualFold(key, "Host")
}

// Apply sets the configured User-Agent (when non-empty) and extra headers on
// req. It is used for direct (non-browser) HTTP fetches.
func (c HTTPConfig) Apply(req *http.Request) {
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	for _, h := range c.Headers {
		if reservedHeader(h.Key) {
			continue
		}
		req.Header.Set(h.Key, h.Value)
	}
}

// HeaderPairs flattens the extra headers into the key,value,key,value… slice
// shape that go-rod's Page.SetExtraHeaders expects, skipping any reserved
// header. Returns nil when there are no applicable headers.
func (c HTTPConfig) HeaderPairs() []string {
	var pairs []string
	for _, h := range c.Headers {
		if reservedHeader(h.Key) {
			continue
		}
		pairs = append(pairs, h.Key, h.Value)
	}
	return pairs
}
