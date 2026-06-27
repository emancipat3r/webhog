package renderer

import (
	"net/http"
	"strings"
)

// defaultUserAgent is the User-Agent webhog sends when the caller does not
// override it via --user-agent.
const defaultUserAgent = "webhog/0.1.0 (https://github.com/user/webhog)"

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
