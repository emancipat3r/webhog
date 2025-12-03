package renderer

import (
	"context"
)

// JSBlob represents a JavaScript code blob found on a page
type JSBlob struct {
	Source string // "inline", "external", "network"
	Path   string // URL or identifier like "URL#inline-N"
	Body   string // The actual JavaScript content
}

// RenderResult contains the rendered page and all discovered JavaScript
type RenderResult struct {
	URL     string   // The final URL (after redirects)
	HTML    string   // The page HTML
	JSBlobs []JSBlob // All JavaScript found
}

// Renderer defines the interface for fetching and rendering web pages
type Renderer interface {
	Render(ctx context.Context, targetURL string) (*RenderResult, error)
}
