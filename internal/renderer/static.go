package renderer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// maxBodyBytes caps how much of any single HTTP response is read into memory,
// guarding against accidental or malicious oversized responses.
const maxBodyBytes = 20 << 20 // 20 MiB

// StaticRenderer fetches pages using HTTP only (no JavaScript execution)
type StaticRenderer struct {
	client  *http.Client
	timeout time.Duration
	httpCfg HTTPConfig
}

// NewStaticRenderer creates a new static renderer. httpCfg customizes the
// User-Agent and headers sent on every request (page and sub-resource fetches);
// pass the zero value for default behavior.
func NewStaticRenderer(timeout time.Duration, httpCfg HTTPConfig) *StaticRenderer {
	return &StaticRenderer{
		client: &http.Client{
			Timeout: timeout,
		},
		timeout: timeout,
		httpCfg: httpCfg,
	}
}

// setRequestHeaders applies the default User-Agent and then the caller's
// HTTPConfig (custom UA and extra headers) to req, so every outbound request
// from this renderer carries the same identity.
func (s *StaticRenderer) setRequestHeaders(req *http.Request) {
	req.Header.Set("User-Agent", defaultUserAgent)
	s.httpCfg.Apply(req)
}

// Render fetches a page and extracts HTML and JavaScript
func (s *StaticRenderer) Render(ctx context.Context, targetURL string) (*RenderResult, error) {
	// Fetch the HTML
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	s.setRequestHeaders(req)

	if err := s.httpCfg.Wait(ctx); err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching page: %w", err)
	}
	defer resp.Body.Close()

	// Scan the response regardless of status code: error pages (403, 401, 500,
	// etc.) frequently leak stack traces, internal endpoints, and credentials,
	// which is exactly what we want for recon.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	htmlContent := string(body)
	finalURL := resp.Request.URL.String()

	// Parse HTML and extract JavaScript
	jsBlobs, resourceErrs, err := s.extractJavaScript(ctx, htmlContent, finalURL)
	if err != nil {
		return nil, fmt.Errorf("extracting JavaScript: %w", err)
	}

	return &RenderResult{
		URL:     finalURL,
		Status:  resp.StatusCode,
		HTML:    htmlContent,
		Headers: resp.Header,
		JSBlobs: jsBlobs,
		Errors:  resourceErrs,
	}, nil
}

// extractJavaScript parses HTML and extracts all JavaScript (inline and external)
func (s *StaticRenderer) extractJavaScript(ctx context.Context, htmlContent, baseURL string) ([]JSBlob, []ResourceError, error) {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing HTML: %w", err)
	}

	var jsBlobs []JSBlob
	var errs []ResourceError
	inlineCounter := 0

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			// Check if it's inline or external
			src := getAttr(n, "src")
			if src != "" {
				// External script. Fetch failures are recorded, not dropped,
				// so a page whose scripts were all refused is distinguishable
				// from a page with no scripts.
				scriptURL, err := resolveURL(baseURL, src)
				if err == nil {
					content, status, err := s.fetchScript(ctx, scriptURL)
					if err != nil {
						errs = append(errs, ResourceError{URL: scriptURL, Err: err.Error()})
					} else {
						jsBlobs = append(jsBlobs, JSBlob{
							Source: "external",
							Path:   scriptURL,
							Body:   content,
							Status: status,
						})
					}
				}
			} else {
				// Inline script
				content := getTextContent(n)
				if strings.TrimSpace(content) != "" {
					inlineCounter++
					jsBlobs = append(jsBlobs, JSBlob{
						Source: "inline",
						Path:   fmt.Sprintf("%s#inline-%d", baseURL, inlineCounter),
						Body:   content,
					})
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
	return jsBlobs, errs, nil
}

// fetchScript fetches an external JavaScript file and returns its body and
// HTTP status. Like the page fetch, the body is returned for every status:
// error pages leak stack traces and internal endpoints, and a 403 from bot
// management is itself a signal the caller wants to see (via Status).
func (s *StaticRenderer) fetchScript(ctx context.Context, scriptURL string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", scriptURL, nil)
	if err != nil {
		return "", 0, err
	}

	s.setRequestHeaders(req)

	if err := s.httpCfg.Wait(ctx); err != nil {
		return "", 0, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", resp.StatusCode, err
	}

	return string(body), resp.StatusCode, nil
}

// getAttr returns the value of an attribute from an HTML node
func getAttr(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

// getTextContent extracts all text content from a node and its children
func getTextContent(n *html.Node) string {
	var buf strings.Builder
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.TextNode {
			buf.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(n)
	return buf.String()
}

// resolveURL resolves a relative URL against a base URL
func resolveURL(baseURL, relativeURL string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	relative, err := url.Parse(relativeURL)
	if err != nil {
		return "", err
	}

	return base.ResolveReference(relative).String(), nil
}
