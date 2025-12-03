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
	var findings []Finding

	// Scan all JS blobs
	for _, blob := range result.JSBlobs {
		findings = append(findings, s.scanBlob(blob)...)
	}

	// Deduplicate findings
	findings = deduplicateFindings(findings)

	return findings
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
