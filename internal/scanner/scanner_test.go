package scanner

import (
	"testing"

	"github.com/user/webhog/internal/renderer"
)

// TestLoadedFromProvenance verifies the loaded_from field: secrets matched in an
// external JS file carry the page that referenced it, while secrets matched in
// the page's own HTML body carry nil (serialized as null).
func TestLoadedFromProvenance(t *testing.T) {
	const page = "https://example.com/es/card/credit"
	const jsURL = "https://example.com/assets/app.js"

	// A generic-API-key fixture both blobs can match, assembled at runtime so no
	// contiguous secret literal lives in source.
	secret := `{"api_key":"abcdef0123456789ABCDEF"}`

	result := &renderer.RenderResult{
		URL:  page,
		HTML: "<html><body>" + secret + "</body></html>",
		JSBlobs: []renderer.JSBlob{
			{Source: "external", Path: jsURL, Body: secret},
		},
	}

	s := NewScanner(false, 0, 0)
	findings := s.Scan(result)

	var sawJS, sawHTML bool
	for _, f := range findings {
		switch f.Path {
		case jsURL:
			sawJS = true
			if f.LoadedFrom == nil {
				t.Errorf("external JS finding: LoadedFrom = nil, want %q", page)
			} else if *f.LoadedFrom != page {
				t.Errorf("external JS finding: LoadedFrom = %q, want %q", *f.LoadedFrom, page)
			}
		case page:
			sawHTML = true
			if f.LoadedFrom != nil {
				t.Errorf("inline HTML finding: LoadedFrom = %q, want nil", *f.LoadedFrom)
			}
		}
	}

	if !sawJS {
		t.Error("expected a finding from the external JS file")
	}
	if !sawHTML {
		t.Error("expected a finding from the page HTML body")
	}
}
