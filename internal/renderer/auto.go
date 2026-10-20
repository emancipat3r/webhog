package renderer

import (
	"context"
	"strings"
	"sync"
)

// AutoRenderer renders statically and falls back to the browser for a
// target whose static answer looks like bot management. The static path
// costs one request and no browser; the fallback costs one more request
// for the page that was blocked, after which every page of that target
// goes through the browser.
type AutoRenderer struct {
	static   Renderer
	headless Sessioner
	onSwitch func(url string) // optional notice when a target switches
}

// NewAutoRenderer composes the two renderers.
func NewAutoRenderer(static Renderer, headless Sessioner, onSwitch func(string)) *AutoRenderer {
	return &AutoRenderer{static: static, headless: headless, onSwitch: onSwitch}
}

// Render serves callers that did not open a session: each page decides on
// its own.
func (a *AutoRenderer) Render(ctx context.Context, targetURL string) (*RenderResult, error) {
	s, err := a.NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Render(ctx, targetURL)
}

// NewSession returns a per-target session that remembers the switch.
func (a *AutoRenderer) NewSession() (Session, error) {
	return &autoSession{parent: a}, nil
}

type autoSession struct {
	parent  *AutoRenderer
	mu      sync.Mutex
	browser Session // non-nil once this target switched to the browser
}

func (s *autoSession) current() Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.browser
}

func (s *autoSession) switchToBrowser(url string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.browser != nil {
		return s.browser, nil
	}
	b, err := s.parent.headless.NewSession()
	if err != nil {
		return nil, err
	}
	s.browser = b
	if s.parent.onSwitch != nil {
		s.parent.onSwitch(url)
	}
	return b, nil
}

func (s *autoSession) Render(ctx context.Context, targetURL string) (*RenderResult, error) {
	if b := s.current(); b != nil {
		return b.Render(ctx, targetURL)
	}
	res, err := s.parent.static.Render(ctx, targetURL)
	if err != nil {
		return nil, err
	}
	if !LooksBlocked(res) {
		return res, nil
	}
	b, err := s.switchToBrowser(targetURL)
	if err != nil {
		return res, nil // the static answer is still an observation
	}
	return b.Render(ctx, targetURL)
}

func (s *autoSession) Close() error {
	if b := s.current(); b != nil {
		return b.Close()
	}
	return nil
}

// blockMarkers are strings that identify a bot-management interstitial or
// denial page in the body, independent of status code.
var blockMarkers = []string{
	"cf-browser-verification", "cf_chl_opt", "challenge-platform", "Just a moment...", "cf-challenge",
	"errors.edgesuite.net", "Reference&#32;&#35;", "Reference #18.",
	"px-captcha", "_pxhc", "PerimeterX", "px-cdn.net",
	"datadome", "DataDome",
	"_Incapsula_Resource", "Incapsula incident", "Request unsuccessful. Incapsula",
	"distil_r_captcha", "Pardon Our Interruption",
	"Kasada", "ips.js?",
	"Attention Required! | Cloudflare",
}

// LooksBlocked decides whether a static response is bot management rather
// than the page: a denial status with a bot-management marker or a small
// body, or any status whose body carries a marker, or a page whose
// scripts were every one refused.
func LooksBlocked(res *RenderResult) bool {
	if res == nil {
		return false
	}
	denied := res.Status == 403 || res.Status == 429 || res.Status == 503 || res.Status == 401
	for _, m := range blockMarkers {
		if strings.Contains(res.HTML, m) {
			return true
		}
	}
	if denied && len(res.HTML) < 8192 {
		return true
	}
	if denied {
		external := 0
		for _, b := range res.JSBlobs {
			if b.Source != "inline" {
				external++
			}
		}
		if external > 0 && res.Refused() >= external {
			return true
		}
	}
	return false
}
