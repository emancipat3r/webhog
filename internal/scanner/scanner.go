package scanner

import (
	"math"
	"strings"

	"github.com/user/webhog/internal/renderer"
)

// Scanner scans rendered pages for secrets and endpoints
type Scanner struct {
	detectors      []Detector
	includeEntropy bool
	minEntropy     float64
	minLength      int
}

// NewScanner creates a new scanner with the given configuration
func NewScanner(includeEntropy bool, minEntropy float64, minLength int) *Scanner {
	return &Scanner{
		detectors:      GetDetectors(),
		includeEntropy: includeEntropy,
		minEntropy:     minEntropy,
		minLength:      minLength,
	}
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
		for _, f := range s.scanBlob(blob) {
			findingsChan <- f
		}
	}
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

// scanBlob scans a single JavaScript blob for secrets
func (s *Scanner) scanBlob(blob renderer.JSBlob) []Finding {
	var findings []Finding

	lines := strings.Split(blob.Body, "\n")

	for lineNum, line := range lines {
		// Run all detectors on this line
		for _, detector := range s.detectors {
			matches := detector.Re.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) < 2 {
					continue
				}

				token := match[1]
				snippet := createSnippet(line, token)

				findings = append(findings, Finding{
					Detector: detector.Name,
					Type:     detector.Type,
					Path:     blob.Path,
					LineNum:  lineNum + 1,
					Snippet:  snippet,
					Token:    token,
				})
			}
		}

		// Optional: Entropy-based detection
		if s.includeEntropy {
			findings = append(findings, s.detectHighEntropy(blob.Path, lineNum+1, line)...)
		}
	}

	return findings
}

// detectHighEntropy finds high-entropy strings that might be secrets
func (s *Scanner) detectHighEntropy(path string, lineNum int, line string) []Finding {
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
				Detector: "High Entropy String",
				Type:     DetectorGeneric,
				Path:     path,
				LineNum:  lineNum,
				Snippet:  snippet,
				Token:    token,
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
