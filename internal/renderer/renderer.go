package renderer

import (
	"context"
)

// JSBlob represents a JavaScript code blob found on a page
type JSBlob struct {
	Source string // "inline", "external", "network"
	Path   string // URL or identifier like "URL#inline-N"
	Body   string // The actual JavaScript content
	// Status is the HTTP status the resource was served with, when it was
	// fetched over the network ("external" and "network" sources). It is 0 for
	// inline scripts and when the status is unknown. Bodies are kept for every
	// status, because error pages leak stack traces and internal endpoints, so a
	// consumer that wants only successful loads must filter on this.
	Status int
}

// ResourceError records an external resource a page referenced that could not
// be retrieved at all (connection failure, blocked by the browser, body not
// readable). Resources that were served with an error status are not listed
// here; they appear as JSBlobs with a non-2xx Status.
type ResourceError struct {
	URL string
	Err string
}

// RenderResult contains the rendered page and all discovered JavaScript
type RenderResult struct {
	URL     string              // The final URL (after redirects)
	Status  int                 // HTTP status code of the main response (0 if unknown)
	HTML    string              // The page HTML
	Headers map[string][]string // HTTP Response Headers
	JSBlobs []JSBlob            // All JavaScript found
	Errors  []ResourceError     // Referenced resources that could not be fetched
}

// Refused counts the external resources of a page that were refused: those
// that could not be fetched at all plus those served with a 4xx/5xx status.
// It lets a consumer distinguish a page with no scripts from a page whose
// scripts were all blocked, which otherwise produce the same finding set.
func (r *RenderResult) Refused() int {
	n := len(r.Errors)
	for _, b := range r.JSBlobs {
		if b.Source != "inline" && b.Status >= 400 {
			n++
		}
	}
	return n
}

// Renderer defines the interface for fetching and rendering web pages
type Renderer interface {
	Render(ctx context.Context, targetURL string) (*RenderResult, error)
}

// Session is a Renderer with its own isolated state (cookies, storage) that
// must be released when the caller is done with it.
type Session interface {
	Renderer
	Close() error
}

// Sessioner is implemented by renderers that can isolate targets from one
// another. Callers scanning several targets should obtain one Session per
// target so state from one host never bleeds into another.
type Sessioner interface {
	NewSession() (Session, error)
}
