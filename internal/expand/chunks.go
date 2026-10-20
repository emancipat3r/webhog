package expand

import (
	"regexp"
	"strings"

	"github.com/emancipat3r/webhog/internal/renderer"
)

// Chunk discovery. A bundler splits an app into a runtime and route chunks
// that the browser only fetches when a route is visited, so a crawl that
// renders the landing page sees a fraction of the code. The runtime carries
// enough to name every chunk: webpack keeps a filename template keyed by
// chunk id, Vite keeps a dependency array, Next.js publishes a build
// manifest, and any bundle names its dynamic imports as string literals.

var (
	dynamicImport = regexp.MustCompile(`import\(\s*["']([^"']+\.[cm]?js)["']\s*\)`)
	viteDeps      = regexp.MustCompile(`viteFileDeps\s*=\s*\[([^\]]*)\]`)
	quoted        = regexp.MustCompile(`["']([^"']+)["']`)
	nextBuildID   = regexp.MustCompile(`"buildId"\s*:\s*"([^"]+)"`)
	nextAssetBase = regexp.MustCompile(`(?:src|href)=["']([^"']*?/_next/)static/`)
	manifestChunk = regexp.MustCompile(`["'](static/(?:chunks|[A-Za-z0-9_-]+)/[^"']+\.js)["']`)
	swRegister    = regexp.MustCompile(`serviceWorker\.register\(\s*["']([^"']+)["']`)
	importScripts = regexp.MustCompile(`importScripts\(([^)]*)\)`)
	precacheURL   = regexp.MustCompile(`["']?url["']?\s*:\s*["']([^"']+\.[cm]?js)["']`)
	preloadLink   = regexp.MustCompile(`(?i)<link[^>]+rel=["'](?:modulepreload|preload)["'][^>]*>`)
	hrefAttr      = regexp.MustCompile(`(?i)href=["']([^"']+)["']`)
	webpackPublic = regexp.MustCompile(`\.p\s*=\s*["']([^"']*)["']`)
	lookupParam   = regexp.MustCompile(`\}\[(\w+)\]`)
	// webpackTemplate locates a chunk filename template: webpack 5's
	// `.u=e=>...` / `.u=function(e){return ...}` or webpack 4's
	// `.p+"..."` inside jsonpScriptSrc. The expression runs to the first
	// string literal ending in .js.
	webpackTemplate = regexp.MustCompile(`(?:\.u\s*=\s*(?:function\s*\(\s*(\w+)\s*\)\s*\{\s*return\s*|\(?\s*(\w+)\s*\)?\s*=>\s*)|\.p\s*\+\s*)([^;]*?\.(?:chunk\.)?js["'])`)
)

// Candidates returns the chunk URLs named by a page and its blobs that are
// not already among the blobs. Paths are resolved against the resource
// that named them (a script's own URL for a webpack template, the page for
// Vite and Next.js manifests).
func chunkCandidates(res *renderer.RenderResult, fetched map[string]bool) []string {
	have := map[string]bool{}
	for _, b := range res.JSBlobs {
		have[b.Path] = true
	}
	var out []string
	add := func(base, ref string) {
		u := resolve(base, ref)
		if u == "" || have[u] || fetched[u] || !isScriptPath(u) {
			return
		}
		have[u] = true
		out = append(out, u)
	}

	// Page-level sources: preload links and the Next.js build id.
	for _, link := range preloadLink.FindAllString(res.HTML, -1) {
		if m := hrefAttr.FindStringSubmatch(link); m != nil {
			add(res.URL, m[1])
		}
	}
	if m := nextBuildID.FindStringSubmatch(res.HTML); m != nil {
		base := "/_next/"
		if a := nextAssetBase.FindStringSubmatch(res.HTML); a != nil {
			base = a[1]
		}
		add(res.URL, base+"static/"+m[1]+"/_buildManifest.js")
	}
	for _, m := range swRegister.FindAllStringSubmatch(res.HTML, -1) {
		add(res.URL, m[1])
	}

	for _, b := range res.JSBlobs {
		if b.Source == "sourcemap" {
			continue
		}
		body := b.Body
		base := b.Path
		if b.Source == "inline" || b.Source == "html" {
			base = res.URL
		}
		for _, m := range dynamicImport.FindAllStringSubmatch(body, -1) {
			add(base, m[1])
		}
		for _, m := range viteDeps.FindAllStringSubmatch(body, -1) {
			for _, q := range quoted.FindAllStringSubmatch(m[1], -1) {
				add(res.URL, q[1])
			}
		}
		if strings.Contains(base, "_buildManifest") {
			prefix := base[:strings.Index(base, "static/")]
			for _, m := range manifestChunk.FindAllStringSubmatch(body, -1) {
				add(prefix, m[1])
			}
		}
		for _, m := range swRegister.FindAllStringSubmatch(body, -1) {
			add(res.URL, m[1])
		}
		for _, m := range importScripts.FindAllStringSubmatch(body, -1) {
			for _, q := range quoted.FindAllStringSubmatch(m[1], -1) {
				add(base, q[1])
			}
		}
		if b.Source == "chunk" && looksLikeServiceWorker(body) {
			for _, m := range precacheURL.FindAllStringSubmatch(body, -1) {
				add(base, m[1])
			}
		}
		for _, u := range webpackChunks(body) {
			add(base, u)
		}
	}
	return out
}

// looksLikeServiceWorker: a precache manifest only means something inside
// a service worker; elsewhere `url:"x.js"` is any object.
func looksLikeServiceWorker(body string) bool {
	return strings.Contains(body, "precache") || strings.Contains(body, "self.addEventListener") || strings.Contains(body, "workbox")
}

// webpackChunks reconstructs every chunk filename a webpack runtime can
// produce. The template is a concatenation of string literals, lookups in
// id-keyed objects, and the chunk id itself; the set of ids is the union
// of the objects' keys. It returns paths relative to the runtime's public
// path, resolved by the caller against the runtime script's URL.
func webpackChunks(body string) []string {
	ms := webpackTemplate.FindAllStringSubmatch(body, -1)
	if len(ms) == 0 {
		return nil
	}
	public := ""
	if m := webpackPublic.FindStringSubmatch(body); m != nil {
		public = m[1]
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range ms {
		param := m[1]
		if param == "" {
			param = m[2]
		}
		expr := m[3]
		if param == "" {
			// webpack 4 form: the parameter is whatever indexes the maps.
			if im := lookupParam.FindStringSubmatch(expr); im != nil {
				param = im[1]
			}
		}
		if param == "" {
			continue
		}
		for _, name := range evalTemplate(expr, param) {
			u := public + name
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
		if len(out) > 5000 {
			break
		}
	}
	return out
}

// term is one piece of a template expression.
type term struct {
	lit      string            // literal text
	lookup   map[string]string // id -> value
	fallback *string           // value when lookup misses: nil means the term is required, "" means the id itself
	isID     bool              // the bare chunk id
}

var (
	objectLit = regexp.MustCompile(`^\{(.*)\}$`)
	objEntry  = regexp.MustCompile(`(?:"([^"]*)"|'([^']*)'|([A-Za-z0-9_$-]+))\s*:\s*(?:"([^"]*)"|'([^']*)'|([0-9]+))`)
)

// splitTop splits expr on + outside quotes, braces and parentheses.
func splitTop(expr string) []string {
	var parts []string
	depth, quote := 0, byte(0)
	start := 0
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case quote != 0:
			if c == quote && (i == 0 || expr[i-1] != '\\') {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '{' || c == '(' || c == '[':
			depth++
		case c == '}' || c == ')' || c == ']':
			depth--
		case c == '+' && depth == 0:
			parts = append(parts, strings.TrimSpace(expr[start:i]))
			start = i + 1
		}
	}
	parts = append(parts, strings.TrimSpace(expr[start:]))
	return parts
}

func parseObject(src string) map[string]string {
	m := objectLit.FindStringSubmatch(src)
	if m == nil {
		return nil
	}
	out := map[string]string{}
	for _, e := range objEntry.FindAllStringSubmatch(m[1], -1) {
		key := e[1] + e[2] + e[3]
		out[key] = e[4] + e[5] + e[6]
	}
	return out
}

// parseTerm classifies one piece of the template.
func parseTerm(src, param string) (term, bool) {
	src = strings.TrimSpace(src)
	if src == "" {
		return term{}, false
	}
	// Strip one layer of parentheses.
	if strings.HasPrefix(src, "(") && strings.HasSuffix(src, ")") {
		src = strings.TrimSpace(src[1 : len(src)-1])
	}
	if (strings.HasPrefix(src, `"`) && strings.HasSuffix(src, `"`)) || (strings.HasPrefix(src, `'`) && strings.HasSuffix(src, `'`)) {
		return term{lit: src[1 : len(src)-1]}, true
	}
	if src == param {
		return term{isID: true}, true
	}
	// {...}[e] with an optional || fallback.
	idx := strings.Index(src, "}["+param+"]")
	if idx < 0 || !strings.HasPrefix(src, "{") {
		return term{}, false
	}
	obj := parseObject(src[:idx+1])
	if obj == nil {
		return term{}, false
	}
	t := term{lookup: obj}
	rest := strings.TrimSpace(src[idx+len("}["+param+"]"):])
	if strings.HasPrefix(rest, "||") {
		fb := strings.TrimSpace(rest[2:])
		switch {
		case fb == param:
			s := ""
			t.fallback = &s
		case len(fb) >= 2 && (fb[0] == '"' || fb[0] == '\''):
			s := fb[1 : len(fb)-1]
			t.fallback = &s
		}
	}
	return t, true
}

// evalTemplate expands the template for every chunk id the lookups know.
func evalTemplate(expr, param string) []string {
	var terms []term
	ids := map[string]bool{}
	for _, p := range splitTop(expr) {
		t, ok := parseTerm(p, param)
		if !ok {
			return nil
		}
		terms = append(terms, t)
		for id := range t.lookup {
			ids[id] = true
		}
	}
	if len(ids) == 0 || len(ids) > 2000 {
		return nil
	}
	var out []string
	for id := range ids {
		var sb strings.Builder
		ok := true
		for _, t := range terms {
			switch {
			case t.isID:
				sb.WriteString(id)
			case t.lookup != nil:
				if v, found := t.lookup[id]; found {
					sb.WriteString(v)
				} else if t.fallback == nil {
					ok = false
				} else if *t.fallback == "" {
					sb.WriteString(id)
				} else {
					sb.WriteString(*t.fallback)
				}
			default:
				sb.WriteString(t.lit)
			}
			if !ok {
				break
			}
		}
		if ok {
			out = append(out, sb.String())
		}
	}
	return out
}
