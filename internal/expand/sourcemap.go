package expand

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/emancipat3r/webhog/internal/renderer"
)

// sourceMappingURL finds the map a script names in its trailing comment.
// Both the `//#` and the older `//@` forms are accepted, as is the block
// comment form bundlers use for CSS and some JS.
var sourceMappingURL = regexp.MustCompile(`(?m)(?://|/\*)[#@]\s*sourceMappingURL=([^\s*]+)`)

// mapComment returns the map reference named in the script's last comment,
// or "". Only the tail of the body is searched: the comment is the last
// line, and a bundle can embed other files' comments higher up.
func mapComment(body string) string {
	tail := body
	if len(tail) > 4096 {
		tail = tail[len(tail)-4096:]
	}
	ms := sourceMappingURL.FindAllStringSubmatch(tail, -1)
	if len(ms) == 0 {
		return ""
	}
	return ms[len(ms)-1][1]
}

// rawMap is the subset of the source map format webhog reads. Indexed maps
// (sections) nest the same shape.
type rawMap struct {
	Version        int       `json:"version"`
	Sources        []string  `json:"sources"`
	SourcesContent []*string `json:"sourcesContent"`
	SourceRoot     string    `json:"sourceRoot"`
	Sections       []struct {
		Map rawMap `json:"map"`
	} `json:"sections"`
}

// isVendorSource reports whether a source path is third-party library code
// bundled into the app. Vendor sources are counted but not mined: they are
// large, public and full of documentation values that look like keys.
func isVendorSource(p string) bool {
	return strings.Contains(p, "/node_modules/") || strings.HasPrefix(p, "node_modules/")
}

// parseMap decodes a source map body into the blobs to scan and a record
// of what it held. ok is false when the body is not a source map (a soft
// 404 page, truncated JSON), in which case nothing is exposed.
func parseMap(mapURL, body string, includeVendor bool) (blobs []renderer.JSBlob, ref renderer.SourceMapRef, ok bool) {
	var m rawMap
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return nil, ref, false
	}
	if m.Version == 0 && len(m.Sources) == 0 && len(m.Sections) == 0 {
		return nil, ref, false
	}
	ref = renderer.SourceMapRef{MapURL: mapURL}
	var walk func(rm rawMap)
	walk = func(rm rawMap) {
		for _, sec := range rm.Sections {
			walk(sec.Map)
		}
		for i, src := range rm.Sources {
			ref.Sources++
			name := src
			if rm.SourceRoot != "" && !strings.Contains(src, "://") {
				name = strings.TrimSuffix(rm.SourceRoot, "/") + "/" + strings.TrimPrefix(src, "/")
			}
			if i >= len(rm.SourcesContent) || rm.SourcesContent[i] == nil || *rm.SourcesContent[i] == "" {
				continue
			}
			ref.WithContent++
			if isVendorSource(name) && !includeVendor {
				ref.VendorSkipped++
				continue
			}
			blobs = append(blobs, renderer.JSBlob{
				Source: "sourcemap",
				Path:   mapURL + "#" + name,
				Body:   *rm.SourcesContent[i],
				Status: 200,
			})
		}
	}
	walk(m)
	return blobs, ref, true
}

// dataURIMap decodes an inline (data: URI) source map.
func dataURIMap(ref string) (string, bool) {
	if !strings.HasPrefix(ref, "data:") {
		return "", false
	}
	comma := strings.IndexByte(ref, ',')
	if comma < 0 {
		return "", false
	}
	meta, payload := ref[5:comma], ref[comma+1:]
	if strings.Contains(meta, ";base64") {
		raw, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return "", false
		}
		return string(raw), true
	}
	return payload, true
}

// sourceMapsFor discovers and fetches the map of each fetched script in the
// result, appending the map's sources as blobs and recording each exposed
// map on the result. A script is tried once per target.
func (e *Expander) sourceMapsFor(ctx context.Context, res *renderer.RenderResult) {
	scripts := append([]renderer.JSBlob(nil), res.JSBlobs...)
	for _, blob := range scripts {
		if blob.Source == "inline" || blob.Source == "sourcemap" || blob.Status < 200 || blob.Status >= 300 {
			continue
		}
		if !isScriptPath(blob.Path) && blob.Source != "chunk" {
			continue
		}
		if e.seenMapScript[blob.Path] {
			continue
		}
		e.seenMapScript[blob.Path] = true

		ref := mapComment(blob.Body)
		var mapURL, body string
		var status int
		switch {
		case ref == "" && e.opts.ProbeMaps && isScriptPath(blob.Path):
			mapURL = probeURL(blob.Path)
		case ref != "":
			if inline, ok := dataURIMap(ref); ok {
				mapURL, body, status = blob.Path+"#inline-map", inline, 200
				break
			}
			mapURL = resolve(blob.Path, ref)
		}
		if mapURL == "" {
			continue
		}
		if body == "" {
			if e.seenMapURL[mapURL] {
				continue
			}
			e.seenMapURL[mapURL] = true
			var err error
			body, status, err = e.fetch.get(ctx, mapURL, e.opts.MaxMapBytes)
			if err != nil || status < 200 || status >= 300 {
				e.stats.MapsTried++
				continue
			}
		}
		e.stats.MapsTried++
		blobs, smr, ok := parseMap(mapURL, body, e.opts.IncludeVendor)
		if !ok {
			continue
		}
		smr.Script = blob.Path
		smr.Referenced = ref != ""
		res.SourceMaps = append(res.SourceMaps, smr)
		res.JSBlobs = append(res.JSBlobs, blobs...)
		e.stats.MapsExposed++
	}
}

// probeURL is the conventional map location: the script URL with ".map"
// appended to its path and the query dropped.
func probeURL(script string) string {
	q := strings.IndexByte(script, '?')
	if q >= 0 {
		script = script[:q]
	}
	return script + ".map"
}
