package renderer

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// HeadlessRenderer renders pages with a headless Chromium driven by rod.
//
// One Chromium process is launched per renderer, lazily on the first Render,
// and reused for every page afterwards. Targets that must not share cookies
// or storage get their own incognito browser context via NewSession; pages
// created through a session live in that context and are discarded with it.
type HeadlessRenderer struct {
	timeout time.Duration // page load budget (navigation through window.onload)
	domWait time.Duration // settle period after load for late JS and fetches
	httpCfg HTTPConfig

	// Process-wide browser, launched on first use. Shared by every session.
	mu        sync.Mutex
	launcher  *launcher.Launcher
	browser   *rod.Browser
	launchErr error
	launches  int // number of browser launches (for tests and diagnostics)

	// Session state: non-nil when this renderer was returned by NewSession, in
	// which case pages are created inside this incognito context.
	context *rod.Browser
	parent  *HeadlessRenderer
}

// NewHeadlessRenderer creates a new headless renderer. httpCfg customizes the
// User-Agent and headers applied at the browser/page level, so they propagate
// to the main document and every sub-resource the browser loads. Pass the zero
// value for default behavior. The browser is not started until the first
// Render, so a renderer whose targets all fail early costs nothing. Call Close
// to shut the browser down.
func NewHeadlessRenderer(timeout time.Duration, httpCfg HTTPConfig) *HeadlessRenderer {
	return &HeadlessRenderer{
		timeout: timeout,
		domWait: DefaultDOMWait,
		httpCfg: httpCfg,
	}
}

// DefaultDOMWait is how long a page is given to settle after window.onload
// before its DOM and captured responses are read. A few seconds catches the
// bulk of post-load script injection and API calls without paying the full
// page timeout on pages that never go idle (analytics beacons, long polling,
// websockets keep many real pages busy indefinitely).
const DefaultDOMWait = 3 * time.Second

// SetDOMWait overrides the post-load settle period. Zero disables it.
func (h *HeadlessRenderer) SetDOMWait(d time.Duration) *HeadlessRenderer {
	if d < 0 {
		d = 0
	}
	h.domWait = d
	return h
}

// root returns the renderer that owns the browser process.
func (h *HeadlessRenderer) root() *HeadlessRenderer {
	if h.parent != nil {
		return h.parent
	}
	return h
}

// sharedBrowser returns the process-wide browser, launching it on first use.
// A launch failure is remembered and returned to every later caller rather
// than retried per page, so an unusable environment fails fast.
func (h *HeadlessRenderer) sharedBrowser() (*rod.Browser, error) {
	r := h.root()
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.browser != nil || r.launchErr != nil {
		return r.browser, r.launchErr
	}

	l := launcher.New()
	if path, found := launcher.LookPath(); found {
		l = l.Bin(path)
	} else {
		// Browser not found, rod will auto-download Chromium.
		fmt.Fprintln(os.Stderr, "Chromium not found. Downloading via rod (this is cached)...")
	}

	r.launches++
	controlURL, err := l.Headless(true).Launch()
	if err != nil {
		l.Cleanup()
		r.launchErr = fmt.Errorf("launching browser: %w", err)
		return nil, r.launchErr
	}

	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		l.Kill()
		l.Cleanup()
		r.launchErr = fmt.Errorf("connecting to browser: %w", err)
		return nil, r.launchErr
	}

	r.launcher = l
	r.browser = browser
	return browser, nil
}

// NewSession returns a renderer whose pages share one fresh incognito browser
// context: cookies, storage and cache are isolated from every other session
// and from the default context. The browser process itself is shared. Close
// the session to dispose of the context.
func (h *HeadlessRenderer) NewSession() (Session, error) {
	browser, err := h.sharedBrowser()
	if err != nil {
		return nil, err
	}
	incognito, err := browser.Incognito()
	if err != nil {
		return nil, fmt.Errorf("creating browser context: %w", err)
	}
	return &HeadlessRenderer{
		timeout: h.timeout,
		domWait: h.domWait,
		httpCfg: h.httpCfg,
		context: incognito,
		parent:  h.root(),
	}, nil
}

// Close releases what this renderer owns: for a session, its incognito
// context; for the root renderer, the browser process. It is safe to call
// Close on a root renderer that never launched a browser.
func (h *HeadlessRenderer) Close() error {
	if h.context != nil {
		return h.context.Close()
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.browser == nil {
		return nil
	}
	err := h.browser.Close()
	h.launcher.Kill()
	h.launcher.Cleanup()
	h.browser, h.launcher = nil, nil
	return err
}

// Render uses a headless browser to render the page and extract JavaScript.
// It returns errors rather than panicking so the CLI can fail gracefully on
// unreachable or misbehaving targets. The page is bound to ctx, so the
// caller's deadline and cancellation apply to every step, including reading
// script bodies.
//
// Every byte webhog reports from headless mode came through Chrome's network
// stack: the main document is navigated by the browser and external scripts
// are read out of the responses the browser itself received (see
// captureBodies). Nothing is re-fetched with Go's HTTP client, whose TLS and
// HTTP/2 fingerprint is what bot management rejects in the first place.
func (h *HeadlessRenderer) Render(ctx context.Context, targetURL string) (*RenderResult, error) {
	browser := h.context
	if browser == nil {
		var err error
		if browser, err = h.sharedBrowser(); err != nil {
			return nil, err
		}
	}

	page, err := browser.Context(ctx).Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, fmt.Errorf("creating page: %w", err)
	}
	defer page.Close()
	page = page.Context(ctx).Timeout(h.timeout)

	return h.renderPage(page, targetURL)
}

// renderPage drives an already-created page: it installs the response
// capture, navigates, waits for the page to settle, and assembles the result.
// The page must already be bound to the caller's context and timeout.
func (h *HeadlessRenderer) renderPage(page *rod.Page, targetURL string) (*RenderResult, error) {
	// Begin capturing the main-document response (headers + status) so
	// technology detection has access to server/cookie headers and we can
	// report the status, mirroring static mode.
	readResponse := h.captureResponse(page)

	// Capture the bodies of scripts (and text API responses) as the browser
	// receives them, so external JS is taken from the browser's own fetches.
	bodies, err := h.captureBodies(page)
	if err != nil {
		return nil, fmt.Errorf("enabling response capture: %w", err)
	}

	// Apply the custom User-Agent and extra headers at the page level BEFORE
	// navigating, so they ride along on the main document and every sub-resource
	// (JS, XHR/fetch, images) the browser requests.
	if err := h.applyRequestOptions(page); err != nil {
		return nil, fmt.Errorf("applying request options: %w", err)
	}

	// Navigate to the target URL. The navigation is the one request webhog
	// originates here; the browser's own sub-resource loads follow from it.
	if err := h.httpCfg.Wait(page.GetContext()); err != nil {
		return nil, err
	}
	if err := page.Navigate(targetURL); err != nil {
		return nil, fmt.Errorf("navigating to %s: %w", targetURL, err)
	}

	// Wait for the page to load.
	if err := page.WaitLoad(); err != nil {
		return nil, fmt.Errorf("waiting for page load: %w", err)
	}

	// Give the page a bounded settle period for post-load JavaScript and the
	// requests it makes. This is deliberately separate from (and much shorter
	// than) the page timeout: waiting for a busy page to go fully idle would
	// burn the whole load budget on every page that never does. Idle waiting
	// is best-effort; a timeout here should not abort the scan.
	if h.domWait > 0 {
		_ = page.WaitIdle(h.domWait)
	}

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

	// Inline scripts come from the DOM; external ones from the captured
	// responses. Let in-flight body reads finish first (bounded, so a hung
	// read cannot outlive the page's own budget).
	jsBlobs, err := h.extractInlineScripts(page, finalURL)
	if err != nil {
		return nil, fmt.Errorf("extracting JavaScript: %w", err)
	}
	bodies.wait(page.GetContext())
	external, resourceErrs := bodies.blobs()
	jsBlobs = append(jsBlobs, external...)

	status, headers := readResponse()

	return &RenderResult{
		URL:     finalURL,
		Status:  status,
		HTML:    htmlContent,
		Headers: headers,
		JSBlobs: jsBlobs,
		Errors:  resourceErrs,
	}, nil
}

// applyRequestOptions sets the configured User-Agent and extra headers on the
// browser page so they propagate to the main document and all sub-resources.
// When no User-Agent override is configured it leaves the browser default
// untouched (preserving current behavior). Setting extra headers enables the
// network domain, which is idempotent with captureResponse.
func (h *HeadlessRenderer) applyRequestOptions(page *rod.Page) error {
	if h.httpCfg.UserAgent != "" {
		if err := page.SetUserAgent(&proto.NetworkSetUserAgentOverride{UserAgent: h.httpCfg.UserAgent}); err != nil {
			return fmt.Errorf("setting user-agent: %w", err)
		}
	}
	if pairs := h.httpCfg.HeaderPairs(); len(pairs) > 0 {
		if _, err := page.SetExtraHeaders(pairs); err != nil {
			return fmt.Errorf("setting extra headers: %w", err)
		}
	}
	return nil
}

// captureResponse subscribes to network events and records the status and
// headers of the first main-document response. It returns a getter that yields
// the captured status (0 if unknown) and headers (nil if none were seen).
// Capture is best-effort: if the network domain cannot be enabled, the getter
// returns zero values.
//
// Two events are needed because Chrome splits the picture: responseReceived
// carries the status and most headers, but omits Set-Cookie, which only
// appears in responseReceivedExtraInfo (the raw wire headers). The two are
// joined on request ID and the raw headers win where both exist.
func (h *HeadlessRenderer) captureResponse(page *rod.Page) func() (int, map[string][]string) {
	var (
		mu      sync.Mutex
		docID   proto.NetworkRequestID
		seen    bool
		status  int
		headers map[string][]string
		extra   = make(map[proto.NetworkRequestID]map[string][]string)
	)

	if err := (proto.NetworkEnable{}).Call(page); err != nil {
		return func() (int, map[string][]string) { return 0, nil }
	}

	toHeaders := func(src proto.NetworkHeaders) map[string][]string {
		out := make(map[string][]string, len(src))
		for k, v := range src {
			out[k] = splitHeaderValues(v.String())
		}
		return out
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
		docID = e.RequestID
		status = e.Response.Status
		headers = toHeaders(e.Response.Headers)
	}, func(e *proto.NetworkResponseReceivedExtraInfo) {
		mu.Lock()
		defer mu.Unlock()
		// Keep raw headers only until the document is identified, then only
		// the document's, so sub-resource traffic cannot grow the map.
		if seen && e.RequestID != docID {
			return
		}
		if !seen && len(extra) > 64 {
			return
		}
		extra[e.RequestID] = toHeaders(e.Headers)
	})()

	return func() (int, map[string][]string) {
		mu.Lock()
		defer mu.Unlock()
		if !seen {
			return 0, nil
		}
		merged := make(map[string][]string, len(headers))
		for k, v := range headers {
			merged[k] = v
		}
		for k, v := range extra[docID] {
			merged[canonicalHeaderKey(merged, k)] = v
		}
		return status, merged
	}
}

// canonicalHeaderKey returns the key already present in m that matches k
// case-insensitively, or k itself. The two CDP events can spell the same
// header differently (HTTP/1.1 case vs HTTP/2 lower-case), and a merged map
// must not end up with both.
func canonicalHeaderKey(m map[string][]string, k string) string {
	for existing := range m {
		if strings.EqualFold(existing, k) {
			return existing
		}
	}
	return k
}

// splitHeaderValues turns a CDP header value back into the individual values
// the server sent. CDP merges repeated headers into one string joined with
// "\n" (Set-Cookie is the everyday case), which technology detection and
// cookie analysis need as separate entries, the way net/http delivers them.
func splitHeaderValues(v string) []string {
	if !strings.Contains(v, "\n") {
		return []string{v}
	}
	parts := strings.Split(v, "\n")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// capturedBody is one network response the browser received, with its body.
type capturedBody struct {
	url    string
	status int
	body   string
	source string // "external" for scripts, "network" for XHR/fetch responses
}

// bodyCapture collects response bodies from the Fetch domain as the browser
// receives them. Bodies are keyed by URL (first response wins) and kept in
// arrival order.
type bodyCapture struct {
	mu     sync.Mutex
	wg     sync.WaitGroup
	order  []string
	byURL  map[string]capturedBody
	errors []ResourceError
}

// captureBodies enables response-stage interception on the page for scripts
// and XHR/fetch traffic and reads each body out of the browser as it arrives.
// The interception is response-stage, so Chrome has already performed the
// request (with its own TLS stack, cookies and headers) before the handler
// sees it; webhog never re-issues the request.
//
// This is deliberately not go-rod's Hijack router: Hijack.LoadResponse
// re-fetches the request through a Go http.Client and would reintroduce the
// Go fingerprint this exists to avoid.
func (h *HeadlessRenderer) captureBodies(page *rod.Page) (*bodyCapture, error) {
	c := &bodyCapture{byURL: make(map[string]capturedBody)}

	patterns := make([]*proto.FetchRequestPattern, 0, len(capturedResourceTypes))
	for _, t := range capturedResourceTypes {
		patterns = append(patterns, &proto.FetchRequestPattern{
			URLPattern:   "*",
			ResourceType: t,
			RequestStage: proto.FetchRequestStageResponse,
		})
	}
	if err := (proto.FetchEnable{Patterns: patterns}).Call(page); err != nil {
		return nil, err
	}

	go page.EachEvent(func(e *proto.FetchRequestPaused) {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.handle(page, e)
		}()
	})()

	return c, nil
}

// capturedResourceTypes are the resource types whose bodies are read out of
// the browser. Scripts are webhog's primary target; XHR/fetch responses are
// captured too because SPAs routinely pull configuration (and credentials)
// from JSON endpoints after load.
var capturedResourceTypes = []proto.NetworkResourceType{
	proto.NetworkResourceTypeScript,
	proto.NetworkResourceTypeXHR,
	proto.NetworkResourceTypeFetch,
}

// handle processes one paused response: reads its body, records it, and
// releases the request so the page can continue. The request is always
// released, even when the body cannot be read, so a capture failure never
// stalls page load.
func (c *bodyCapture) handle(page *rod.Page, e *proto.FetchRequestPaused) {
	defer func() {
		_ = (proto.FetchContinueRequest{RequestID: e.RequestID}).Call(page)
	}()

	url := e.Request.URL
	source := "network"
	if e.ResourceType == proto.NetworkResourceTypeScript {
		source = "external"
	}

	if e.ResponseErrorReason != "" {
		c.addError(url, string(e.ResponseErrorReason))
		return
	}
	if e.ResponseStatusCode == nil {
		// Request stage; should not happen with response-stage patterns.
		return
	}
	status := *e.ResponseStatusCode
	if status >= 300 && status < 400 {
		// Redirect hop: no body. The final hop is paused separately.
		return
	}
	// Only keep text-like XHR/fetch bodies; scripts are always kept.
	if source == "network" && !isTextResponse(e.ResponseHeaders) {
		return
	}

	res, err := (proto.FetchGetResponseBody{RequestID: e.RequestID}).Call(page)
	if err != nil {
		c.addError(url, "reading body: "+err.Error())
		return
	}
	body := res.Body
	if res.Base64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(res.Body)
		if err != nil {
			c.addError(url, "decoding body: "+err.Error())
			return
		}
		body = string(decoded)
	}
	if len(body) > maxBodyBytes {
		body = body[:maxBodyBytes]
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.byURL[url]; dup {
		return
	}
	c.byURL[url] = capturedBody{url: url, status: status, body: body, source: source}
	c.order = append(c.order, url)
}

func (c *bodyCapture) addError(url, msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errors = append(c.errors, ResourceError{URL: url, Err: msg})
}

// wait blocks until every in-flight body read has finished or ctx is done.
func (c *bodyCapture) wait(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// blobs returns the captured bodies as JS blobs, in arrival order, plus the
// resources that could not be read.
func (c *bodyCapture) blobs() ([]JSBlob, []ResourceError) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]JSBlob, 0, len(c.order))
	for _, u := range c.order {
		b := c.byURL[u]
		out = append(out, JSBlob{Source: b.source, Path: b.url, Body: b.body, Status: b.status})
	}
	return out, append([]ResourceError(nil), c.errors...)
}

// isTextResponse reports whether the response's Content-Type is one worth
// scanning as text (JSON, JavaScript, XML, or any text/* type). Binary XHR
// payloads (images, blobs, protobuf) are skipped.
func isTextResponse(headers []*proto.FetchHeaderEntry) bool {
	for _, hd := range headers {
		if !strings.EqualFold(hd.Name, "content-type") {
			continue
		}
		ct := strings.ToLower(hd.Value)
		return strings.HasPrefix(ct, "text/") ||
			strings.Contains(ct, "json") ||
			strings.Contains(ct, "javascript") ||
			strings.Contains(ct, "ecmascript") ||
			strings.Contains(ct, "xml")
	}
	// No Content-Type: assume text so nothing interesting is dropped.
	return true
}

// extractInlineScripts returns the page's inline <script> bodies from the
// rendered DOM. External scripts are not fetched here; they are taken from the
// browser's own responses via captureBodies.
func (h *HeadlessRenderer) extractInlineScripts(page *rod.Page, baseURL string) ([]JSBlob, error) {
	var jsBlobs []JSBlob
	inlineCounter := 0

	scripts, err := page.Elements("script")
	if err != nil {
		return nil, fmt.Errorf("finding script elements: %w", err)
	}

	for _, script := range scripts {
		src, err := script.Attribute("src")
		if err == nil && src != nil && *src != "" {
			continue
		}
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

	return jsBlobs, nil
}
