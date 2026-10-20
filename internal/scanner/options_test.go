package scanner

import (
	"fmt"
	"strings"
	"testing"

	"github.com/emancipat3r/webhog/internal/renderer"
)

func scanBody(opts Options, path, body string) []Finding {
	return scanOne(opts, &renderer.RenderResult{
		URL:     "https://www.example.com/",
		HTML:    "<html></html>",
		JSBlobs: []renderer.JSBlob{{Source: "external", Path: path, Body: body, Status: 200}},
	})
}

func scanOne(opts Options, res *renderer.RenderResult) []Finding {
	return NewScanner(opts).Scan(res)
}

func names(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Detector)
	}
	return out
}

func TestIncludeAndExcludeSelectDetectors(t *testing.T) {
	body := `{"api_key":"abcdef0123456789ABCDEF99"} "/api/v1/users"`
	all := scanBody(Options{}, "https://www.example.com/a.js", body)
	if len(all) < 2 {
		t.Fatalf("expected a generic and an endpoint finding, got %v", names(all))
	}
	only := scanBody(Options{Include: []string{"endpoint"}}, "https://www.example.com/a.js", body)
	for _, f := range only {
		if f.Type != DetectorEndpoint {
			t.Errorf("--detectors endpoint still produced %s", f.Detector)
		}
	}
	if len(only) == 0 {
		t.Error("--detectors endpoint produced nothing")
	}
	none := scanBody(Options{Exclude: []string{"generic", "API Endpoint", "relative url"}}, "https://www.example.com/a.js", body)
	for _, f := range none {
		if f.Type == DetectorGeneric || f.Detector == "API Endpoint" || f.Detector == "Relative URL" {
			t.Errorf("excluded detector %s still ran", f.Detector)
		}
	}
	if err := ValidateDetectorNames([]string{"generic", "Stripe API Key"}); err != nil {
		t.Errorf("valid names rejected: %v", err)
	}
	if err := ValidateDetectorNames([]string{"Stripe API Kee"}); err == nil {
		t.Error("typo accepted")
	}
}

// TestGenericValuesMustLookRandom covers the noise filter: identifiers,
// placeholders and prose captured by the Generic rules are dropped, values
// with the shape of a credential stay.
func TestGenericValuesMustLookRandom(t *testing.T) {
	drop := []string{
		`token = localStorage.getItem.bind.apply`,
		`api_key: "YOUR_API_KEY_GOES_HERE_PLEASE"`,
		`password: "********************"`,
		`secret: "<%= ENV['CLIENT_SECRET'] %>"`,
		`authToken = "{{ auth_token_from_server }}"`,
		`password="passwordpasswordpassword"`,
		`apikey="example_api_key_for_docs_1"`,
	}
	for _, line := range drop {
		if got := scanBody(Options{}, "https://www.example.com/a.js", line); len(got) != 0 {
			t.Errorf("%q: expected no generic finding, got %v (%q)", line, names(got), got[0].Token)
		}
	}
	keep := []string{
		`api_key: "sk9d8f7g6h5j4k3l2m1n0b9v8c7x"`,
		`token: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"`,
		`password = "Tr0ub4dor&3-xkcd-936"`,
	}
	for _, line := range keep {
		if got := scanBody(Options{}, "https://www.example.com/a.js", line); len(got) == 0 {
			t.Errorf("%q: expected a generic finding, got none", line)
		}
	}
}

// TestGenericCapCountsOverflow: more than the cap of one Generic detector in
// one file keeps the first cap rows and records the rest on the last row.
// A named detector in the same file is not capped.
func TestGenericCapCountsOverflow(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&sb, "token: \"t0k3n%02dx9y8z7w6v5u4a3b2c1d0e9f\"\n", i)
	}
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&sb, "k%02d = \"AIzaSyA-9dZ3l8Bx_qWmEr0tUvWxYz12-Ab%02dCd\"\n", i, i)
	}
	got := scanBody(Options{GenericCap: 5}, "https://www.example.com/a.js", sb.String())
	generic, named, overflow := 0, 0, 0
	for _, f := range got {
		switch f.Detector {
		case "Generic Token":
			generic++
			overflow += f.Overflow
		case "Google API Key":
			named++
		}
	}
	if generic != 5 || overflow != 25 {
		t.Errorf("cap 5: generic rows %d (want 5), overflow %d (want 25)", generic, overflow)
	}
	if named != 30 {
		t.Errorf("named detector was capped: %d rows, want 30", named)
	}
	uncapped := scanBody(Options{GenericCap: -1}, "https://www.example.com/a.js", sb.String())
	if g := len(uncapped) - 30; g != 30 {
		t.Errorf("cap -1: generic rows %d, want 30", g)
	}
	exact := scanBody(Options{GenericCap: 30}, "https://www.example.com/a.js", sb.String())
	for _, f := range exact {
		if f.Overflow != 0 {
			t.Errorf("exactly at the cap: overflow %d recorded", f.Overflow)
		}
	}
}

// TestThirdPartyLabelAndFirstPartyOnly: a script from another registered
// domain is labelled third party; with FirstPartyOnly it is not mined at
// all, while the page body and same-domain scripts still are.
func TestThirdPartyLabelAndFirstPartyOnly(t *testing.T) {
	key := `{"api_key":"abcdef0123456789ABCDEF99"}`
	res := &renderer.RenderResult{
		URL:  "https://www.example.com/",
		HTML: "<html>" + key + "</html>",
		JSBlobs: []renderer.JSBlob{
			{Source: "external", Path: "https://cdn.example.com/own.js", Body: key + "/*own*/", Status: 200},
			{Source: "external", Path: "https://www.googletagmanager.com/gtm.js", Body: key + "/*gtm*/", Status: 200},
		},
	}
	got := scanOne(Options{ScopeDomain: "example.com"}, res)
	byPath := map[string]Finding{}
	for _, f := range got {
		byPath[f.Path] = f
	}
	if f, ok := byPath["https://www.googletagmanager.com/gtm.js"]; !ok || !f.ThirdParty {
		t.Errorf("gtm.js finding missing or not third party: %+v", f)
	}
	if f := byPath["https://cdn.example.com/own.js"]; f.ThirdParty {
		t.Error("same registered domain labelled third party")
	}
	if f := byPath["https://www.example.com/"]; f.ThirdParty {
		t.Error("page body labelled third party")
	}
	fp := scanOne(Options{ScopeDomain: "example.com", FirstPartyOnly: true}, res)
	for _, f := range fp {
		if strings.Contains(f.Path, "googletagmanager") {
			t.Errorf("first-party-only still mined %s", f.Path)
		}
	}
	if len(fp) != 2 {
		t.Errorf("first-party-only: %d findings, want 2 (page + own.js): %v", len(fp), names(fp))
	}
	// Without a scope domain nothing is third party.
	for _, f := range scanOne(Options{}, res) {
		if f.ThirdParty {
			t.Errorf("no scope domain, yet %s is third party", f.Path)
		}
	}
}

// TestIdenticalBodiesAreScannedOnce: the same bundle under two URLs, or on
// two pages, is mined once; the second occurrence is counted as deduped.
func TestIdenticalBodiesAreScannedOnce(t *testing.T) {
	key := `{"api_key":"abcdef0123456789ABCDEF99"}`
	s := NewScanner(Options{})
	page := func(u, js string) *renderer.RenderResult {
		return &renderer.RenderResult{URL: u, HTML: "<html></html>",
			JSBlobs: []renderer.JSBlob{{Source: "external", Path: js, Body: key, Status: 200}}}
	}
	a := s.Scan(page("https://www.example.com/a", "https://www.example.com/static/app.js"))
	b := s.Scan(page("https://www.example.com/b", "https://www.example.com/static/app.js?v=2"))
	if len(a) != 1 || len(b) != 0 {
		t.Errorf("first page %d findings (want 1), second page %d (want 0)", len(a), len(b))
	}
	if s.Deduped() != 1 {
		t.Errorf("deduped = %d, want 1", s.Deduped())
	}
	// A different body under the same path is new.
	c := s.Scan(page("https://www.example.com/c", "https://www.example.com/static/app.js"))
	if len(c) != 0 {
		t.Errorf("identical body under the original path scanned again: %d", len(c))
	}
	d := s.Scan(&renderer.RenderResult{URL: "https://www.example.com/d", HTML: "<html></html>",
		JSBlobs: []renderer.JSBlob{{Source: "external", Path: "https://www.example.com/static/app.js", Body: key + "// changed", Status: 200}}})
	if len(d) != 1 {
		t.Errorf("changed body not scanned: %d findings", len(d))
	}
}
