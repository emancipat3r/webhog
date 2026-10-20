package scanner

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/emancipat3r/webhog/internal/renderer"
)

// DefaultGenericCap is the default number of matches one Generic detector may
// report from one file before the rest are counted instead of listed.
const DefaultGenericCap = 20

// Options configures a Scanner.
type Options struct {
	IncludeEntropy bool
	MinEntropy     float64
	MinLength      int
	// Include restricts scanning to the named detectors (case-insensitive
	// detector names, or the type words secret, config, endpoint, generic).
	// Empty means every detector.
	Include []string
	// Exclude removes the named detectors (same vocabulary as Include).
	Exclude []string
	// GenericCap caps how many matches each Generic detector reports from one
	// file; 0 means DefaultGenericCap, a negative value disables the cap.
	GenericCap int
	// ScopeDomain is the registered domain of the scan target. When set,
	// findings in resources served from another registered domain are marked
	// third party, and FirstPartyOnly skips those resources entirely.
	ScopeDomain    string
	FirstPartyOnly bool
}

// Scanner scans rendered pages for secrets and endpoints
type Scanner struct {
	detectors      []Detector
	includeEntropy bool
	minEntropy     float64
	minLength      int
	genericCap     int
	scopeDomain    string
	firstPartyOnly bool
	anyKeyword     bool
	seenBodies     map[string]string // body hash -> path first scanned under
	deduped        int
}

// NewScanner creates a new scanner with the given configuration. Unknown
// names in Include or Exclude are reported by ValidateDetectorNames; here
// they are ignored.
func NewScanner(opts Options) *Scanner {
	cap := opts.GenericCap
	if cap == 0 {
		cap = DefaultGenericCap
	}
	s := &Scanner{
		detectors:      selectDetectors(GetDetectors(), opts.Include, opts.Exclude),
		includeEntropy: opts.IncludeEntropy,
		minEntropy:     opts.MinEntropy,
		minLength:      opts.MinLength,
		genericCap:     cap,
		scopeDomain:    strings.ToLower(opts.ScopeDomain),
		firstPartyOnly: opts.FirstPartyOnly,
		seenBodies:     make(map[string]string),
	}
	for _, d := range s.detectors {
		if d.Keyword != "" {
			s.anyKeyword = true
		}
	}
	return s
}

// Detectors returns the detectors this scanner runs, in order.
func (s *Scanner) Detectors() []Detector {
	return s.detectors
}

// typeWords are the shorthand names accepted in Include and Exclude for a
// whole detector type.
var typeWords = map[string]DetectorType{
	"secret":    DetectorSecret,
	"secrets":   DetectorSecret,
	"config":    DetectorConfig,
	"endpoint":  DetectorEndpoint,
	"endpoints": DetectorEndpoint,
	"generic":   DetectorGeneric,
}

// matchesName reports whether a detector is named by sel: its name, case-
// insensitively, or its type word.
func matchesName(d Detector, sel string) bool {
	sel = strings.ToLower(strings.TrimSpace(sel))
	if sel == "" {
		return false
	}
	if t, ok := typeWords[sel]; ok {
		return d.Type == t
	}
	return strings.ToLower(d.Name) == sel
}

// selectDetectors applies the include and exclude lists.
func selectDetectors(all []Detector, include, exclude []string) []Detector {
	var out []Detector
	for _, d := range all {
		keep := len(include) == 0
		for _, sel := range include {
			if matchesName(d, sel) {
				keep = true
				break
			}
		}
		for _, sel := range exclude {
			if matchesName(d, sel) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, d)
		}
	}
	return out
}

// ValidateDetectorNames returns an error naming the first selector that
// matches no detector and no type word, so a typo on the command line is
// reported instead of silently scanning for nothing.
func ValidateDetectorNames(selectors []string) error {
	all := GetDetectors()
	for _, sel := range selectors {
		if strings.TrimSpace(sel) == "" {
			continue
		}
		found := false
		for _, d := range all {
			if matchesName(d, sel) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unknown detector %q (see webhog detectors)", sel)
		}
	}
	return nil
}

// DetectorNames returns every detector name in table order.
func DetectorNames() []string {
	var names []string
	for _, d := range GetDetectors() {
		names = append(names, d.Name)
	}
	return names
}

// sortedDetails is a helper for deterministic output of Details maps.
func sortedDetails(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Scan processes a RenderResult and returns all findings
func (s *Scanner) Scan(result *renderer.RenderResult) []Finding {
	findingsChan := make(chan Finding)
	var findings []Finding

	// Start streaming in a goroutine
	go func() {
		defer close(findingsChan)
		s.ScanStream(result, findingsChan)
	}()

	// Collect findings
	for f := range findingsChan {
		findings = append(findings, f)
	}

	// Deduplicate findings (still useful for final report)
	findings = deduplicateFindings(findings)

	return findings
}

// ScanStream processes a RenderResult and sends findings to the provided channel
func (s *Scanner) ScanStream(result *renderer.RenderResult, findingsChan chan<- Finding) {
	for _, blob := range scanTargets(result) {
		loadedFrom := loadedFromFor(blob, result.URL)
		for _, f := range s.scanBlob(blob, loadedFrom) {
			findingsChan <- f
		}
	}
}

// loadedFromFor returns the provenance for findings produced from blob: the URL
// of the page that referenced it. For an external (or network) JS file that is
// the page currently being crawled (result.URL), i.e. the immediate parent in
// the crawl path. For the page's own HTML body the resource IS the page, so
// there is no separate loader and it returns "" (recorded as null on findings).
func loadedFromFor(blob renderer.JSBlob, pageURL string) string {
	if blob.Source == "html" {
		return ""
	}
	return pageURL
}

// loadedFromPtr converts a loaded-from URL into the optional value carried on a
// Finding: nil (serialized as null) for the empty page-body case, otherwise a
// pointer to the loader URL.
func loadedFromPtr(loadedFrom string) *string {
	if loadedFrom == "" {
		return nil
	}
	return &loadedFrom
}

// scanTargets returns the blobs a page is scanned over: external scripts plus
// the page HTML. Inline scripts are excluded because their content is already
// part of the HTML; scanning both would report every inline match twice under
// different paths.
func scanTargets(result *renderer.RenderResult) []renderer.JSBlob {
	var targets []renderer.JSBlob
	for _, blob := range result.JSBlobs {
		if blob.Source == "inline" {
			continue
		}
		targets = append(targets, blob)
	}
	if result.HTML != "" {
		targets = append(targets, renderer.JSBlob{
			Source: "html",
			Path:   result.URL,
			Body:   result.HTML,
		})
	}
	return targets
}

// ExtractEndpoints runs only the endpoint detectors over a page and returns the
// distinct, fetchable endpoint tokens it finds (absolute http(s) URLs and
// absolute paths). It is used to expand the crawl frontier with URLs discovered
// inside JavaScript and HTML, not just <a href> links.
func (s *Scanner) ExtractEndpoints(result *renderer.RenderResult) []string {
	seen := make(map[string]bool)
	var endpoints []string

	for _, blob := range scanTargets(result) {
		for _, line := range strings.Split(blob.Body, "\n") {
			for _, detector := range s.detectors {
				if detector.Type != DetectorEndpoint {
					continue
				}
				for _, match := range detector.Re.FindAllStringSubmatch(line, -1) {
					if len(match) < 2 {
						continue
					}
					token := match[1]
					if !isFetchableEndpoint(token) || seen[token] {
						continue
					}
					seen[token] = true
					endpoints = append(endpoints, token)
				}
			}
		}
	}

	return endpoints
}

// isFetchableEndpoint reports whether an endpoint token is worth queuing as a
// crawl target: an absolute path or an http(s) URL. This filters out
// non-navigable matches like ws:// URLs and bare "graphql" content-type
// strings that the endpoint detectors can also catch.
func isFetchableEndpoint(token string) bool {
	return strings.HasPrefix(token, "/") ||
		strings.HasPrefix(token, "http://") ||
		strings.HasPrefix(token, "https://")
}

// scanBlob scans a single JavaScript blob for secrets. loadedFrom is the URL of
// the page that referenced this blob (empty when the blob is the page's own
// body), threaded onto every finding so consumers know where the resource in
// Path was loaded from.
func (s *Scanner) scanBlob(blob renderer.JSBlob, loadedFrom string) []Finding {
	var findings []Finding

	thirdParty := s.isThirdParty(blob)
	if thirdParty && s.firstPartyOnly {
		return nil
	}
	if s.alreadyScanned(blob) {
		return nil
	}

	lines := strings.Split(blob.Body, "\n")

	for lineNum, line := range lines {
		var lower string
		if s.anyKeyword {
			lower = strings.ToLower(line)
		}
		// Run all detectors on this line
		for _, detector := range s.detectors {
			if detector.Keyword != "" && !strings.Contains(lower, detector.Keyword) {
				continue
			}
			matches := detector.Re.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) < 2 {
					continue
				}

				token := match[1]
				if detector.Type == DetectorGeneric && !genericLooksLikeACredential(token) {
					continue
				}
				snippet := createSnippet(line, token)

				f := Finding{
					Detector:   detector.Name,
					Type:       detector.Type,
					Path:       blob.Path,
					LineNum:    lineNum + 1,
					Snippet:    snippet,
					Token:      token,
					LoadedFrom: loadedFromPtr(loadedFrom),
					Public:     detector.Public,
					ThirdParty: thirdParty,
				}
				enrich(&f)
				findings = append(findings, f)
			}
		}

		// Optional: Entropy-based detection
		if s.includeEntropy {
			findings = append(findings, s.detectHighEntropy(blob.Path, lineNum+1, line, loadedFrom)...)
		}
	}

	return capGeneric(findings, s.genericCap)
}

// isThirdParty reports whether a fetched resource is served from a registered
// domain other than the scan target's. The page's own body and inline
// scripts are never third party; without a scope domain nothing is.
func (s *Scanner) isThirdParty(blob renderer.JSBlob) bool {
	if s.scopeDomain == "" || blob.Source == "html" || blob.Source == "inline" {
		return false
	}
	return !renderer.SameRegisteredDomain(s.scopeDomain, blob.Path)
}

// alreadyScanned records the blob's body hash and reports whether an
// identical body was scanned before under another path (the same bundle
// served from two URLs, or loaded by every page of a crawl). Findings are
// reported once, under the first path; see ScanStats.
func (s *Scanner) alreadyScanned(blob renderer.JSBlob) bool {
	if blob.Source == "html" || blob.Source == "inline" || blob.Body == "" {
		return false
	}
	h := renderer.BodyHash(blob.Body)
	if _, seen := s.seenBodies[h]; seen {
		s.deduped++
		return true
	}
	s.seenBodies[h] = blob.Path
	return false
}

// Deduped returns how many fetched resources were skipped because a byte-
// identical body had already been scanned in this scanner's lifetime.
func (s *Scanner) Deduped() int {
	return s.deduped
}

// detectHighEntropy finds high-entropy strings that might be secrets
func (s *Scanner) detectHighEntropy(path string, lineNum int, line string, loadedFrom string) []Finding {
	var findings []Finding

	// Tokenize the line (simple word splitting)
	tokens := strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '"' || r == '\'' || r == ',' || r == ';'
	})

	for _, token := range tokens {
		if len(token) < s.minLength {
			continue
		}

		entropy := calculateEntropy(token)
		if entropy >= s.minEntropy {
			snippet := createSnippet(line, token)
			findings = append(findings, Finding{
				Detector:   "High Entropy String",
				Type:       DetectorGeneric,
				Path:       path,
				LineNum:    lineNum,
				Snippet:    snippet,
				Token:      token,
				LoadedFrom: loadedFromPtr(loadedFrom),
			})
		}
	}

	return findings
}

// calculateEntropy calculates Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	var entropy float64
	length := float64(len(s))

	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// createSnippet creates a context snippet around a token
func createSnippet(line, token string) string {
	const maxLen = 100

	idx := strings.Index(line, token)
	if idx == -1 {
		if len(line) > maxLen {
			return line[:maxLen] + "..."
		}
		return line
	}

	start := idx - 20
	if start < 0 {
		start = 0
	}

	end := idx + len(token) + 20
	if end > len(line) {
		end = len(line)
	}

	snippet := line[start:end]
	if start > 0 {
		snippet = "..." + snippet
	}
	if end < len(line) {
		snippet = snippet + "..."
	}

	return snippet
}

// deduplicateFindings removes duplicate findings based on token and path
func deduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var unique []Finding

	for _, f := range findings {
		// Create a unique key based on detector, path, and token
		key := f.Detector + "|" + f.Path + "|" + f.Token
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}

	return unique
}
