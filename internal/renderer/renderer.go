package renderer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
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

// BodyHash returns the hex SHA-256 of a resource body. It identifies a
// script independently of the URL it was served from.
func BodyHash(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

// RegisteredDomain returns the eTLD+1 of a URL's host ("example.com" for
// "api.example.com"), lower-cased. It falls back to the bare host when the
// public-suffix lookup fails (IP addresses, localhost).
func RegisteredDomain(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// SameRegisteredDomain reports whether raw's host shares the given registered
// domain. An empty domain matches nothing.
func SameRegisteredDomain(domain, raw string) bool {
	return domain != "" && RegisteredDomain(raw) == strings.ToLower(domain)
}
