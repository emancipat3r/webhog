package crawler

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

// skipExtensions lists URL path extensions that are not worth fetching as crawl
// targets (static assets, media, archives). Their contents are either binary or
// already reachable as JS blobs during scanning.
var skipExtensions = map[string]bool{
	".css": true, ".js": true, ".mjs": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".webp": true, ".ico": true, ".bmp": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".pdf": true, ".zip": true, ".gz": true, ".tar": true, ".rar": true,
	".mp4": true, ".webm": true, ".mp3": true, ".wav": true, ".avi": true, ".mov": true,
	".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
}

// normalizeURL returns a canonical form of raw used for deduplication and
// fetching: the fragment is dropped and the host is lower-cased. On parse
// failure it returns raw unchanged.
func normalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

// hostOf returns the lower-cased hostname (no port) of raw.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// registeredDomain returns the eTLD+1 of the URL's host (e.g. "example.com" for
// "api.example.com"). It falls back to the bare host when the public-suffix
// lookup fails (e.g. for IPs or localhost).
func registeredDomain(raw string) string {
	host := hostOf(raw)
	if host == "" {
		return ""
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// sameRegisteredDomain reports whether raw shares a registered domain with the
// given seed domain.
func sameRegisteredDomain(seedDomain, raw string) bool {
	return seedDomain != "" && registeredDomain(raw) == seedDomain
}

// anchorHrefs returns the raw href values of <a> elements in the HTML, skipping
// empty and pure-fragment hrefs. Resolution, scheme filtering, and
// deduplication are handled by the crawler so anchors and discovered endpoints
// flow through the same pipeline.
func anchorHrefs(htmlContent string) []string {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil
	}

	var hrefs []string
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key != "href" {
					continue
				}
				href := strings.TrimSpace(attr.Val)
				if href != "" && !strings.HasPrefix(href, "#") {
					hrefs = append(hrefs, href)
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)

	return hrefs
}
