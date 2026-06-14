package renderer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
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

// Render uses a headless browser to render the page and extract JavaScript.
// It returns errors rather than panicking so the CLI can fail gracefully on
// unreachable or misbehaving targets.
func (h *HeadlessRenderer) Render(ctx context.Context, targetURL string) (*RenderResult, error) {
	// Launch browser with auto-download support.
	l := launcher.New()
	defer l.Cleanup()

	if path, found := launcher.LookPath(); found {
		l = l.Bin(path)
	} else {
		// Browser not found, rod will auto-download Chromium.
		fmt.Fprintln(os.Stderr, "Chromium not found. Downloading via rod (this is cached)...")
	}

	controlURL, err := l.Headless(true).Launch()
	if err != nil {
		return nil, fmt.Errorf("launching browser: %w", err)
	}

	// Bind the browser to the caller's context so cancellation/timeout works.
	browser := rod.New().ControlURL(controlURL).Context(ctx)
	if err := browser.Connect(); err != nil {
		return nil, fmt.Errorf("connecting to browser: %w", err)
	}
	defer browser.Close()

	page, err := browser.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, fmt.Errorf("creating page: %w", err)
	}
	defer page.Close()
	page = page.Timeout(h.timeout)

	// Begin capturing the main-document response (headers + status) so
	// technology detection has access to server/cookie headers and we can
	// report the status, mirroring static mode.
	readResponse := h.captureResponse(page)

	// Navigate to the target URL.
	if err := page.Navigate(targetURL); err != nil {
		return nil, fmt.Errorf("navigating to %s: %w", targetURL, err)
	}

	// Wait for the page to load.
	if err := page.WaitLoad(); err != nil {
		return nil, fmt.Errorf("waiting for page load: %w", err)
	}

	// Give additional time for JavaScript execution. Idle waiting is
	// best-effort; a timeout here should not abort the whole scan.
	_ = page.WaitIdle(h.timeout)

	// Get the final URL (after redirects).
	info, err := page.Info()
	if err != nil {
		return nil, fmt.Errorf("getting page info: %w", err)
	}
	finalURL := info.URL

	// Extract HTML.
	htmlContent, err := page.HTML()
	if err != nil {
		return nil, fmt.Errorf("extracting HTML: %w", err)
	}

	// Extract JavaScript.
	jsBlobs, err := h.extractJavaScript(page, finalURL)
	if err != nil {
		return nil, fmt.Errorf("extracting JavaScript: %w", err)
	}

	status, headers := readResponse()

	return &RenderResult{
		URL:     finalURL,
		Status:  status,
		HTML:    htmlContent,
		Headers: headers,
		JSBlobs: jsBlobs,
	}, nil
}

// captureResponse subscribes to network events and records the status and
// headers of the first main-document response. It returns a getter that yields
// the captured status (0 if unknown) and headers (nil if none were seen).
// Capture is best-effort: if the network domain cannot be enabled, the getter
// returns zero values.
func (h *HeadlessRenderer) captureResponse(page *rod.Page) func() (int, map[string][]string) {
	var (
		mu      sync.Mutex
		seen    bool
		status  int
		headers map[string][]string
	)

	if err := (proto.NetworkEnable{}).Call(page); err != nil {
		return func() (int, map[string][]string) { return 0, nil }
	}

	go page.EachEvent(func(e *proto.NetworkResponseReceived) {
		if e.Type != proto.NetworkResourceTypeDocument {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if seen {
			return
		}
		seen = true
		status = e.Response.Status
		captured := make(map[string][]string, len(e.Response.Headers))
		for k, v := range e.Response.Headers {
			captured[k] = []string{v.String()}
		}
		headers = captured
	})()

	return func() (int, map[string][]string) {
		mu.Lock()
		defer mu.Unlock()
		return status, headers
	}
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", err
	}

	return string(body), nil
}
