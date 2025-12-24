package renderer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
)

// HeadlessRenderer uses a headless browser (rod) to render pages
type HeadlessRenderer struct {
	timeout time.Duration
}

// NewHeadlessRenderer creates a new headless renderer
func NewHeadlessRenderer(timeout time.Duration) *HeadlessRenderer {
	return &HeadlessRenderer{
		timeout: timeout,
	}
}

// Render uses a headless browser to render the page and extract JavaScript
func (h *HeadlessRenderer) Render(ctx context.Context, targetURL string) (*RenderResult, error) {
	// Launch browser with auto-download support
	l := launcher.New()

	// Check if a browser is already installed
	path, found := launcher.LookPath()
	if !found {
		// Browser not found, rod will auto-download Chromium
		fmt.Fprintln(os.Stderr, "Chromium not found. Downloading via rod (this is cached)...")
	} else {
		l = l.Bin(path)
	}

	// Launch headless browser
	controlURL := l.Headless(true).MustLaunch()
	browser := rod.New().ControlURL(controlURL).MustConnect()
	defer browser.MustClose()

	// Create a new page with timeout
	page := browser.Timeout(h.timeout).MustPage()
	defer page.MustClose()

	// Navigate to the target URL
	if err := page.Navigate(targetURL); err != nil {
		return nil, fmt.Errorf("navigating to %s: %w", targetURL, err)
	}

	// Wait for the page to load
	if err := page.WaitLoad(); err != nil {
		return nil, fmt.Errorf("waiting for page load: %w", err)
	}

	// Give additional time for JavaScript execution
	page.MustWaitIdle()

	// Get the final URL (after redirects)
	finalURL := page.MustInfo().URL

	// Extract HTML
	html, err := page.HTML()
	if err != nil {
		return nil, fmt.Errorf("extracting HTML: %w", err)
	}

	// Extract JavaScript
	jsBlobs, err := h.extractJavaScript(page, finalURL)
	if err != nil {
		return nil, fmt.Errorf("extracting JavaScript: %w", err)
	}

	return &RenderResult{
		URL:     finalURL,
		HTML:    html,
		Headers: nil, // TODO: Capture headers via request interception
		JSBlobs: jsBlobs,
	}, nil
}

// extractJavaScript extracts all JavaScript from the page
func (h *HeadlessRenderer) extractJavaScript(page *rod.Page, baseURL string) ([]JSBlob, error) {
	var jsBlobs []JSBlob
	inlineCounter := 0

	// Get all script elements
	scripts, err := page.Elements("script")
	if err != nil {
		return nil, fmt.Errorf("finding script elements: %w", err)
	}

	for _, script := range scripts {
		// Check if it has a src attribute (external)
		src, err := script.Attribute("src")
		if err == nil && src != nil && *src != "" {
			// External script - fetch content
			scriptURL := *src

			// Resolve relative URLs
			if !strings.HasPrefix(scriptURL, "http") {
				scriptURL, err = resolveURL(baseURL, scriptURL)
				if err != nil {
					continue
				}
			}

			content, err := h.fetchScript(scriptURL)
			if err == nil {
				jsBlobs = append(jsBlobs, JSBlob{
					Source: "external",
					Path:   scriptURL,
					Body:   content,
				})
			}
		} else {
			// Inline script
			text, err := script.Text()
			if err == nil && strings.TrimSpace(text) != "" {
				inlineCounter++
				jsBlobs = append(jsBlobs, JSBlob{
					Source: "inline",
					Path:   fmt.Sprintf("%s#inline-%d", baseURL, inlineCounter),
					Body:   text,
				})
			}
		}
	}

	return jsBlobs, nil
}

// fetchScript fetches an external JavaScript file
func (h *HeadlessRenderer) fetchScript(scriptURL string) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("GET", scriptURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "webhog/0.1.0 (https://github.com/user/webhog)")

	resp, err := client.Do(req)
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
