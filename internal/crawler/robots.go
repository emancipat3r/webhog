package crawler

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxRobotsBytes = 1 << 20 // 1 MiB

// RobotsTargets fetches /robots.txt for the seed's origin and returns absolute
// URLs worth crawling that are listed there: the paths in Disallow/Allow rules
// (which commonly point at admin panels, internal tools, exports, and staging
// areas) and any Sitemap: URLs.
//
// The rules are used purely as an enumeration source — webhog intentionally
// does NOT honor their crawl-restriction intent. This is meant for authorized
// recon (bug bounty, pentests) where disallowed paths are exactly what you want
// to inspect. It issues a single GET and adds no crawl load beyond the paths it
// discovers (still bounded by --max-pages). Returns nil if robots.txt is absent
// or unreadable.
func RobotsTargets(ctx context.Context, seedURL string, client *http.Client) []string {
	base, err := url.Parse(seedURL)
	if err != nil || base.Host == "" {
		return nil
	}
	robotsURL := base.Scheme + "://" + base.Host + "/robots.txt"

	req, err := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "webhog/0.1.0 (https://github.com/user/webhog)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var targets []string
	seen := make(map[string]bool)
	add := func(raw string) {
		ref, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			return
		}
		abs := base.ResolveReference(ref).String()
		if !seen[abs] {
			seen[abs] = true
			targets = append(targets, abs)
		}
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, maxRobotsBytes))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "disallow", "allow":
			if p := cleanRobotsPath(value); p != "" {
				add(p)
			}
		case "sitemap":
			if value != "" {
				add(value)
			}
		}
	}

	return targets
}

// cleanRobotsPath turns a robots.txt path pattern into a fetchable path,
// trimming the `*`/`$` wildcard syntax. It returns "" for patterns that carry
// no useful path (empty, non-absolute, or the whole-site "/").
func cleanRobotsPath(p string) string {
	if i := strings.IndexAny(p, "*$"); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimSpace(p)
	if p == "" || p == "/" || !strings.HasPrefix(p, "/") {
		return ""
	}
	return p
}
