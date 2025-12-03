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

// StaticRenderer fetches pages using HTTP only (no JavaScript execution)
type StaticRenderer struct {
	client  *http.Client
	timeout time.Duration
}

// NewStaticRenderer creates a new static renderer
func NewStaticRenderer(timeout time.Duration) *StaticRenderer {
	return &StaticRenderer{
		client: &http.Client{
			Timeout: timeout,
		},
		timeout: timeout,
	}
}

// Render fetches a page and extracts HTML and JavaScript
func (s *StaticRenderer) Render(ctx context.Context, targetURL string) (*RenderResult, error) {
	// Fetch the HTML
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("User-Agent", "webhog/0.1.0 (https://github.com/user/webhog)")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	htmlContent := string(body)
	finalURL := resp.Request.URL.String()

	// Parse HTML and extract JavaScript
	jsBlobs, err := s.extractJavaScript(ctx, htmlContent, finalURL)
	if err != nil {
		return nil, fmt.Errorf("extracting JavaScript: %w", err)
	}

	return &RenderResult{
		URL:     finalURL,
		HTML:    htmlContent,
		JSBlobs: jsBlobs,
	}, nil
}

// extractJavaScript parses HTML and extracts all JavaScript (inline and external)
func (s *StaticRenderer) extractJavaScript(ctx context.Context, htmlContent, baseURL string) ([]JSBlob, error) {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("parsing HTML: %w", err)
	}

	var jsBlobs []JSBlob
	inlineCounter := 0

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			// Check if it's inline or external
			src := getAttr(n, "src")
			if src != "" {
				// External script
				scriptURL, err := resolveURL(baseURL, src)
				if err == nil {
					content, err := s.fetchScript(ctx, scriptURL)
					if err == nil {
						jsBlobs = append(jsBlobs, JSBlob{
							Source: "external",
							Path:   scriptURL,
							Body:   content,
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
	return jsBlobs, nil
}

// fetchScript fetches an external JavaScript file
func (s *StaticRenderer) fetchScript(ctx context.Context, scriptURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", scriptURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "webhog/0.1.0 (https://github.com/user/webhog)")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
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
