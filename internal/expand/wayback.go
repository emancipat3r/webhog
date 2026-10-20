package expand

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/emancipat3r/webhog/internal/renderer"
)

// DefaultWaybackBase is the CDX index and archive origin.
const DefaultWaybackBase = "https://web.archive.org"

// DefaultMaxWayback caps how many historical scripts are fetched per target.
const DefaultMaxWayback = 100

// waybackScripts asks the Wayback Machine's CDX index for the JavaScript
// URLs it has captured under the target's host. Old bundles carry keys
// that were rotated out of the live ones, and routes that were removed.
// It returns (original URL, capture timestamp) pairs, newest capture per
// URL, most recent first; the index is asked for a few times the fetch
// cap, since scripts the live page still loads are skipped later.
func (e *Expander) waybackScripts(ctx context.Context, host string, limit int) [][2]string {
	base := e.opts.WaybackBase
	if base == "" {
		base = DefaultWaybackBase
	}
	q := url.Values{}
	q.Set("url", host+"/*")
	q.Set("output", "json")
	q.Set("fl", "original,timestamp,statuscode")
	q.Set("filter", "mimetype:.*javascript.*")
	q.Add("filter", "statuscode:200")
	q.Set("collapse", "urlkey")
	q.Set("limit", "-"+itoa(limit*5)) // newest captures first, room for duplicates
	body, status, err := e.fetch.get(ctx, base+"/cdx/search/cdx?"+q.Encode(), 16<<20)
	if err != nil || status != 200 {
		return nil
	}
	var rows [][]string
	if json.Unmarshal([]byte(body), &rows) != nil || len(rows) < 2 {
		return nil
	}
	seen := map[string]bool{}
	var out [][2]string
	for _, row := range rows[1:] {
		if len(row) < 2 {
			continue
		}
		orig := row[0]
		if seen[orig] || !isScriptPath(orig) {
			continue
		}
		seen[orig] = true
		out = append(out, [2]string{orig, row[1]})
	}
	return out
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

// waybackFor runs once per target, on the first page rendered: it fetches
// the historical scripts that are not already among the page's blobs. With
// Archived set the copies come from the archive itself, so the target sees
// no request for them; otherwise the live URL is fetched and a script that
// is gone is recorded as refused.
func (e *Expander) waybackFor(ctx context.Context, res *renderer.RenderResult) {
	if e.waybackDone {
		return
	}
	e.waybackDone = true
	u, err := url.Parse(res.URL)
	if err != nil {
		return
	}
	limit := e.opts.MaxWayback
	if limit <= 0 {
		limit = DefaultMaxWayback
	}
	have := map[string]bool{}
	for _, b := range res.JSBlobs {
		have[strings.SplitN(b.Path, "?", 2)[0]] = true
	}
	base := e.opts.WaybackBase
	if base == "" {
		base = DefaultWaybackBase
	}
	for _, pair := range e.waybackScripts(ctx, u.Hostname(), limit) {
		orig, ts := pair[0], pair[1]
		if have[strings.SplitN(orig, "?", 2)[0]] || e.fetchedChunks[orig] {
			continue
		}
		if ctx.Err() != nil || e.stats.WaybackFetched >= limit {
			return
		}
		e.fetchedChunks[orig] = true
		e.stats.WaybackFetched++
		fetchURL, source := orig, "wayback"
		if e.opts.WaybackArchived {
			fetchURL, source = base+"/web/"+ts+"id_/"+orig, "wayback-archived"
		}
		body, status, err := e.fetch.get(ctx, fetchURL, 0)
		if err != nil {
			res.Errors = append(res.Errors, renderer.ResourceError{URL: fetchURL, Err: err.Error()})
			continue
		}
		path := orig
		if e.opts.WaybackArchived {
			path = orig + "#archived-" + ts
		}
		res.JSBlobs = append(res.JSBlobs, renderer.JSBlob{Source: source, Path: path, Body: body, Status: status})
	}
}
