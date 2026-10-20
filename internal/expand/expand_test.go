package expand

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emancipat3r/webhog/internal/renderer"
	"github.com/emancipat3r/webhog/internal/scanner"
)

// site is a local server standing in for a bundled single-page app. It
// counts requests per path so tests can assert what was fetched and how
// often. Nothing here leaves the loopback interface.
type site struct {
	*httptest.Server
	mu    sync.Mutex
	hits  map[string]int
	pages map[string]page
}

type page struct {
	status int
	ctype  string
	body   string
}

func newSite(t *testing.T, pages map[string]page) *site {
	t.Helper()
	s := &site{hits: map[string]int{}, pages: pages}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits[r.URL.Path]++
		s.mu.Unlock()
		p, ok := s.pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if p.ctype != "" {
			w.Header().Set("Content-Type", p.ctype)
		}
		if p.status != 0 {
			w.WriteHeader(p.status)
		}
		_, _ = w.Write([]byte(p.body))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *site) hit(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

func mapJSON(sources []string, content []string) string {
	m := map[string]any{"version": 3, "sources": sources, "sourcesContent": content, "mappings": "AAAA"}
	b, _ := json.Marshal(m)
	return string(b)
}

// fake credentials are assembled from fragments so no credential-shaped
// literal sits in source.
var (
	stripeKey = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
	googleKey = "AIza" + "SyA-9dZ3l8Bx_qWmEr0tUvWxYz12-Ab34Cd"
	ghToken   = "ghp_" + strings.Repeat("Ab1", 12)
)

func render(t *testing.T, s *site, path string, opts Options) (*renderer.RenderResult, *Expander) {
	t.Helper()
	inner := renderer.NewStaticRenderer(5*time.Second, renderer.HTTPConfig{})
	f := NewFetcher(5*time.Second, renderer.HTTPConfig{}, 0)
	e := New(inner, f, opts)
	res, err := e.Render(context.Background(), s.URL+path)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return res, e
}

func paths(res *renderer.RenderResult, source string) []string {
	var out []string
	for _, b := range res.JSBlobs {
		if b.Source == source {
			out = append(out, b.Path)
		}
	}
	return out
}

func has(list []string, suffix string) bool {
	for _, s := range list {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}

// TestWebpackRuntimeNamesEveryChunk reconstructs chunk filenames from a
// webpack 5 runtime (name map with fallback, hash map, public path) and
// fetches them, then follows a dynamic import inside a fetched chunk.
func TestWebpackRuntimeNamesEveryChunk(t *testing.T) {
	runtime := `(()=>{var r={};n.p="/static/js/";n.u=e=>"chunks/"+({12:"admin",34:"settings"}[e]||e)+"."+{12:"a1b2c3",34:"d4e5f6",56:"778899"}[e]+".chunk.js";n.miniCssF=e=>"css/"+e+".css"})();`
	s := newSite(t, map[string]page{
		"/":                     {body: `<html><script src="/static/js/runtime.js"></script></html>`, ctype: "text/html"},
		"/static/js/runtime.js": {body: runtime},
		"/static/js/chunks/admin.a1b2c3.chunk.js":    {body: `import("./deeper.js"); var k="` + stripeKey + `";`},
		"/static/js/chunks/settings.d4e5f6.chunk.js": {body: `console.log(1)`},
		"/static/js/chunks/56.778899.chunk.js":       {body: `console.log(2)`},
		"/static/js/chunks/deeper.js":                {body: `var g="` + googleKey + `";`},
	})
	res, e := render(t, s, "/", Options{Chunks: true, SourceMaps: false})
	chunks := paths(res, "chunk")
	for _, want := range []string{"admin.a1b2c3.chunk.js", "settings.d4e5f6.chunk.js", "56.778899.chunk.js", "deeper.js"} {
		if !has(chunks, want) {
			t.Errorf("chunk %s not fetched; got %v", want, chunks)
		}
	}
	if has(chunks, ".css") {
		t.Errorf("a css template was treated as a chunk: %v", chunks)
	}
	if st := e.Stats(); st.ChunksFetched != 4 {
		t.Errorf("ChunksFetched = %d, want 4", st.ChunksFetched)
	}
	findings := scanner.NewScanner(scanner.Options{}).Scan(res)
	var sawStripe, sawGoogle bool
	for _, f := range findings {
		if f.Detector == "Stripe API Key" && strings.HasSuffix(f.Path, "admin.a1b2c3.chunk.js") {
			sawStripe = true
		}
		if f.Detector == "Google API Key" && strings.HasSuffix(f.Path, "deeper.js") {
			sawGoogle = true
		}
	}
	if !sawStripe || !sawGoogle {
		t.Errorf("secrets in chunks not found: stripe=%v google=%v", sawStripe, sawGoogle)
	}
	// A second page of the same target fetches nothing again.
	s.pages["/two"] = page{body: `<html><script src="/static/js/runtime.js"></script></html>`, ctype: "text/html"}
	if _, err := e.Render(context.Background(), s.URL+"/two"); err != nil {
		t.Fatal(err)
	}
	if n := s.hit("/static/js/chunks/admin.a1b2c3.chunk.js"); n != 1 {
		t.Errorf("admin chunk fetched %d times across two pages, want 1", n)
	}
}

// TestWebpackFourTemplate covers the older jsonpScriptSrc form, where the
// public path is concatenated inside the template.
func TestWebpackFourTemplate(t *testing.T) {
	names := webpackChunks(`function jsonpScriptSrc(e){return o.p+"static/js/"+({1:"vendors"}[e]||e)+"."+{1:"abc123",2:"def456"}[e]+".chunk.js"}`)
	want := map[string]bool{"static/js/vendors.abc123.chunk.js": true, "static/js/2.def456.chunk.js": true}
	if len(names) != 2 {
		t.Fatalf("got %v", names)
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected %q", n)
		}
	}
	// A template with a required map drops ids the map lacks.
	only := webpackChunks(`.u=function(e){return ""+e+"."+{7:"aaaa"}[e]+".js"}`)
	if len(only) != 1 || only[0] != "7.aaaa.js" {
		t.Errorf("got %v", only)
	}
	if got := webpackChunks(`var x = 1;`); got != nil {
		t.Errorf("no template, got %v", got)
	}
}

// TestNextViteAndServiceWorkerSources covers the three manifest shapes
// that are not a webpack template.
func TestNextViteAndServiceWorkerSources(t *testing.T) {
	s := newSite(t, map[string]page{
		"/next":                                   {ctype: "text/html", body: `<html><script id="__NEXT_DATA__" type="application/json">{"props":{},"buildId":"B1"}</script><script src="/_next/static/chunks/main-abc.js"></script></html>`},
		"/_next/static/chunks/main-abc.js":        {body: `console.log("main")`},
		"/_next/static/B1/_buildManifest.js":      {body: `self.__BUILD_MANIFEST={"/admin":["static/chunks/pages/admin-123.js"],"/":["static/chunks/pages/index-456.js"]}`},
		"/_next/static/chunks/pages/admin-123.js": {body: `var t="` + ghToken + `"`},
		"/_next/static/chunks/pages/index-456.js": {body: `ok`},
		"/vite":                {ctype: "text/html", body: `<html><script type="module" src="/assets/index-abc.js"></script><link rel="modulepreload" href="/assets/pre-999.js"></html>`},
		"/assets/index-abc.js": {body: `const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/Admin-xyz.js","assets/style.css"])))=>i.map(i=>d[i]); __vite__mapDeps.viteFileDeps=["assets/Admin-xyz.js","assets/style.css"];`},
		"/assets/Admin-xyz.js": {body: `ok`},
		"/assets/pre-999.js":   {body: `ok`},
		"/sw":                  {ctype: "text/html", body: `<html><script>navigator.serviceWorker.register("/sw.js")</script></html>`},
		"/sw.js":               {body: `importScripts("https://example.invalid/wb.js"); workbox.precaching.precacheAndRoute([{url:"/precached/x.js",revision:"1"},{url:"/precached/img.png",revision:"2"}])`},
		"/precached/x.js":      {body: `ok`},
	})
	res, _ := render(t, s, "/next", Options{Chunks: true})
	if c := paths(res, "chunk"); !has(c, "_buildManifest.js") || !has(c, "admin-123.js") || !has(c, "index-456.js") {
		t.Errorf("next chunks: %v", c)
	}
	res, _ = render(t, s, "/vite", Options{Chunks: true})
	if c := paths(res, "chunk"); !has(c, "Admin-xyz.js") || !has(c, "pre-999.js") || has(c, ".css") {
		t.Errorf("vite chunks: %v", c)
	}
	res, _ = render(t, s, "/sw", Options{Chunks: true})
	if c := paths(res, "chunk"); !has(c, "/sw.js") || !has(c, "/precached/x.js") || has(c, "img.png") {
		t.Errorf("service worker chunks: %v", c)
	}
}

// TestChunkCapIsCounted: candidates beyond --max-chunks are counted, not
// fetched.
func TestChunkCapIsCounted(t *testing.T) {
	pages := map[string]page{"/": {ctype: "text/html", body: `<html><script src="/r.js"></script></html>`}}
	pages["/r.js"] = page{body: `n.u=e=>e+"."+{1:"a",2:"b",3:"c",4:"d",5:"e"}[e]+".js"`}
	for _, n := range []string{"1.a", "2.b", "3.c", "4.d", "5.e"} {
		pages["/"+n+".js"] = page{body: "ok"}
	}
	s := newSite(t, pages)
	_, e := render(t, s, "/", Options{Chunks: true, MaxChunks: 2})
	if st := e.Stats(); st.ChunksFetched != 2 || st.ChunksCapped != 3 {
		t.Errorf("stats %+v, want 2 fetched, 3 capped", st)
	}
}

// TestSourceMapsReferencedProbedAndSoft404 covers the three outcomes: a
// script's comment names a map that exists, a script with no comment whose
// conventional .map exists, and a probe answered by a 200 HTML page that is
// not a map. Vendor sources inside a map are counted but not mined.
func TestSourceMapsReferencedProbedAndSoft404(t *testing.T) {
	appMap := mapJSON(
		[]string{"webpack://app/src/config.ts", "webpack://app/node_modules/lib/index.js"},
		[]string{`export const key = "` + stripeKey + `";`, `// lib\nconst k = "` + googleKey + `";`})
	vendorMap := mapJSON([]string{"src/vendor-entry.js"}, []string{`token: "` + ghToken + `"`})
	s := newSite(t, map[string]page{
		"/":              {ctype: "text/html", body: `<html><script src="/app.js"></script><script src="/vendor.js?v=3"></script><script src="/soft.js"></script><script src="/none.js"></script></html>`},
		"/app.js":        {body: "var a=1;\n//# sourceMappingURL=app.js.map"},
		"/app.js.map":    {body: appMap, ctype: "application/json"},
		"/vendor.js":     {body: "var v=1;"},
		"/vendor.js.map": {body: vendorMap},
		"/soft.js":       {body: "var s=1;"},
		"/soft.js.map":   {body: "<html>not found</html>", ctype: "text/html"},
		"/none.js":       {body: "var n=1;"},
	})
	res, e := render(t, s, "/", Options{SourceMaps: true, ProbeMaps: true})
	if st := e.Stats(); st.MapsTried != 4 || st.MapsExposed != 2 {
		t.Errorf("stats %+v, want 4 tried, 2 exposed", st)
	}
	if n := s.hit("/vendor.js.map"); n != 1 {
		t.Errorf("probe for vendor.js.map hit %d times, want 1 (query dropped)", n)
	}
	byMap := map[string]renderer.SourceMapRef{}
	for _, sm := range res.SourceMaps {
		byMap[sm.MapURL] = sm
	}
	app := byMap[s.URL+"/app.js.map"]
	if !app.Referenced || app.Sources != 2 || app.WithContent != 2 || app.VendorSkipped != 1 {
		t.Errorf("app map ref %+v", app)
	}
	if v := byMap[s.URL+"/vendor.js.map"]; v.Referenced || v.Sources != 1 {
		t.Errorf("vendor map ref %+v", v)
	}
	srcs := paths(res, "sourcemap")
	if !has(srcs, "#webpack://app/src/config.ts") || has(srcs, "node_modules/lib/index.js") || !has(srcs, "#src/vendor-entry.js") {
		t.Errorf("sourcemap blobs: %v", srcs)
	}

	findings := scanner.NewScanner(scanner.Options{}).Scan(res)
	var exposed int
	var stripeInSource, googleFromVendor, ghFromVendorMap bool
	for _, f := range findings {
		switch {
		case f.Detector == "Source Map Exposed":
			exposed++
			if f.Details["sources"] == "" {
				t.Errorf("exposure finding without details: %+v", f)
			}
		case f.Detector == "Stripe API Key" && strings.HasSuffix(f.Path, "#webpack://app/src/config.ts"):
			stripeInSource = true
		case f.Detector == "Google API Key":
			googleFromVendor = true
		case f.Detector == "GitHub Personal Access Token" && strings.Contains(f.Path, "vendor.js.map#"):
			ghFromVendorMap = true
		}
	}
	if exposed != 2 || !stripeInSource || googleFromVendor || !ghFromVendorMap {
		t.Errorf("exposed=%d stripe=%v googleFromVendor=%v ghFromVendorMap=%v", exposed, stripeInSource, googleFromVendor, ghFromVendorMap)
	}

	// Vendor sources are mined on request.
	res, _ = render(t, s, "/", Options{SourceMaps: true, ProbeMaps: true, IncludeVendor: true})
	if !has(paths(res, "sourcemap"), "node_modules/lib/index.js") {
		t.Error("IncludeVendor did not mine the vendor source")
	}
	// Probing off: only the referenced map is tried.
	_, e = render(t, s, "/", Options{SourceMaps: true, ProbeMaps: false})
	if st := e.Stats(); st.MapsTried != 1 || st.MapsExposed != 1 {
		t.Errorf("no probe: stats %+v", st)
	}
}

// TestInlineDataURIMapNeedsNoRequest decodes a base64 data: map in place.
func TestInlineDataURIMapNeedsNoRequest(t *testing.T) {
	m := mapJSON([]string{"src/a.ts"}, []string{`const t = "` + ghToken + `";`})
	data := "data:application/json;charset=utf-8;base64," + base64.StdEncoding.EncodeToString([]byte(m))
	s := newSite(t, map[string]page{
		"/":     {ctype: "text/html", body: `<html><script src="/a.js"></script></html>`},
		"/a.js": {body: "var a=1;\n//# sourceMappingURL=" + data},
	})
	res, e := render(t, s, "/", Options{SourceMaps: true, ProbeMaps: true})
	if st := e.Stats(); st.MapsTried != 1 || st.MapsExposed != 1 {
		t.Errorf("stats %+v", st)
	}
	if s.hit("/a.js.map") != 0 {
		t.Error("probed a .map although the script carried an inline map")
	}
	if !has(paths(res, "sourcemap"), "#src/a.ts") {
		t.Errorf("inline map sources not mined: %v", paths(res, "sourcemap"))
	}
}

// TestMapCommentTakesTheLastOne: a bundle that embeds other files' trailing
// comments higher up still resolves to its own, final comment.
func TestMapCommentTakesTheLastOne(t *testing.T) {
	body := "//# sourceMappingURL=inner.js.map\nvar x;\n/*# sourceMappingURL=outer.js.map */"
	if got := mapComment(body); got != "outer.js.map" {
		t.Errorf("got %q", got)
	}
	if got := mapComment("no comment here"); got != "" {
		t.Errorf("got %q", got)
	}
}

// TestWaybackFetchesHistoricalScripts: the CDX index names three scripts;
// one is still loaded by the live page and is skipped, one is fetched
// live, one is gone from the host and recorded as refused. With Archived
// the copies come from the archive and the host sees no request.
func TestWaybackFetchesHistoricalScripts(t *testing.T) {
	var archiveHits, liveOld int
	var cdx *httptest.Server
	app := newSite(t, map[string]page{
		"/":              {ctype: "text/html", body: `<html><script src="/static/app.js"></script></html>`},
		"/static/app.js": {body: `var live = 1;`},
		"/static/old.js": {body: `var old = "ghp_` + strings.Repeat("Ab1", 12) + `";`},
	})
	cdx = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/cdx/search/cdx"):
			if r.URL.Query().Get("url") == "" || !strings.Contains(r.URL.Query()["filter"][0], "javascript") {
				t.Errorf("unexpected CDX query %s", r.URL.RawQuery)
			}
			rows := [][]string{{"original", "timestamp", "statuscode"},
				{app.URL + "/static/app.js", "20240101000000", "200"},
				{app.URL + "/static/old.js", "20230601000000", "200"},
				{app.URL + "/static/gone.js", "20220101000000", "200"},
				{app.URL + "/static/old.js", "20230101000000", "200"},
				{app.URL + "/page.html", "20230101000000", "200"},
			}
			_ = json.NewEncoder(w).Encode(rows)
		case strings.HasPrefix(r.URL.Path, "/web/"):
			archiveHits++
			_, _ = w.Write([]byte(`var archived = "AIza` + `SyA-9dZ3l8Bx_qWmEr0tUvWxYz12-Ab34Cd";`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cdx.Close)

	res, e := render(t, app, "/", Options{Wayback: true, WaybackBase: cdx.URL})
	liveOld = app.hit("/static/old.js")
	wb := paths(res, "wayback")
	if !has(wb, "/static/old.js") || !has(wb, "/static/gone.js") || has(wb, "/static/app.js") || has(wb, "page.html") {
		t.Errorf("wayback blobs %v", wb)
	}
	if liveOld != 1 || app.hit("/static/app.js") != 1 {
		t.Errorf("live fetches: old.js %d (want 1), app.js %d (want 1)", liveOld, app.hit("/static/app.js"))
	}
	if st := e.Stats(); st.WaybackFetched != 2 {
		t.Errorf("WaybackFetched = %d, want 2", st.WaybackFetched)
	}
	var gone bool
	for _, b := range res.JSBlobs {
		if strings.HasSuffix(b.Path, "/static/gone.js") && b.Status == 404 {
			gone = true
		}
	}
	if !gone {
		t.Error("a script gone from the host should be a 404 blob")
	}
	found := scanner.NewScanner(scanner.Options{}).Scan(res)
	if len(found) == 0 || found[0].Detector != "GitHub Personal Access Token" {
		t.Errorf("secret in the historical script not found: %v", found)
	}

	// Archived copies: the host is not asked for them at all.
	before := app.hit("/static/old.js")
	res, _ = render(t, app, "/", Options{Wayback: true, WaybackArchived: true, WaybackBase: cdx.URL})
	if app.hit("/static/old.js") != before || archiveHits != 2 {
		t.Errorf("archived mode: host hits %d (want %d), archive hits %d (want 2)", app.hit("/static/old.js"), before, archiveHits)
	}
	arch := paths(res, "wayback-archived")
	if !has(arch, "/static/old.js#archived-20230601000000") {
		t.Errorf("archived blobs %v", arch)
	}
	// Second page of the same target: the index is not asked again.
	app.pages["/two"] = page{ctype: "text/html", body: `<html></html>`}
	e2 := New(renderer.NewStaticRenderer(5*time.Second, renderer.HTTPConfig{}), NewFetcher(5*time.Second, renderer.HTTPConfig{}, 0), Options{Wayback: true, WaybackBase: cdx.URL, MaxWayback: 1})
	if _, err := e2.Render(context.Background(), app.URL+"/"); err != nil {
		t.Fatal(err)
	}
	if _, err := e2.Render(context.Background(), app.URL+"/two"); err != nil {
		t.Fatal(err)
	}
	if st := e2.Stats(); st.WaybackFetched != 1 {
		t.Errorf("MaxWayback 1 across two pages: fetched %d", st.WaybackFetched)
	}
}
