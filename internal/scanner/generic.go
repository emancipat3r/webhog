package scanner

import (
	"strings"
)

// genericStopwords are fragments that mark a generic match as a placeholder,
// template or code rather than a credential value. Matching is on the
// lower-cased token.
var genericStopwords = []string{
	"example", "your_", "yourkey", "your-", "xxxx", "changeme", "placeholder",
	"redacted", "dummy", "sample", "insert", "replace", "<", ">", "{{", "${",
	"undefined", "function", "process.env", "window.", "document.", "localstorage",
	"sessionstorage", "getitem", "******", "......", "password", "secret",
}

// genericLooksLikeACredential decides whether a value captured by one of the
// Generic detectors is worth reporting. The Generic rules anchor on a keyword
// and take whatever follows the assignment operator, so they also capture
// identifiers, placeholders, prose and template markers. A credential value
// is random: it has digits, and its character distribution is spread. The
// thresholds step with the digit count because a long random string with no
// digit at all is rare (about 3 in 100 for 20 characters), so such a value
// has to be more spread to pass.
func genericLooksLikeACredential(token string) bool {
	t := strings.TrimSpace(token)
	if t == "" {
		return false
	}
	lower := strings.ToLower(t)
	for _, w := range genericStopwords {
		if strings.Contains(lower, w) {
			return false
		}
	}
	digits := 0
	for _, r := range t {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	entropy := calculateEntropy(t)
	switch {
	case digits == 0:
		return entropy >= 4.0
	case digits == 1:
		return entropy >= 3.5
	default:
		return entropy >= 3.0
	}
}

// capGeneric enforces the per-file cap on generic findings: for each generic
// detector, only the first cap matches in a blob are kept, and the last kept
// finding records how many were dropped. Named detectors are never capped;
// a real key is worth a row however many times a bundle repeats it. cap <= 0
// disables the cap.
func capGeneric(findings []Finding, cap int) []Finding {
	if cap <= 0 {
		return findings
	}
	kept := make([]Finding, 0, len(findings))
	count := map[string]int{}
	last := map[string]int{} // detector -> index in kept of its last finding
	dropped := map[string]int{}
	for _, f := range findings {
		if f.Type != DetectorGeneric {
			kept = append(kept, f)
			continue
		}
		count[f.Detector]++
		if count[f.Detector] > cap {
			dropped[f.Detector]++
			continue
		}
		kept = append(kept, f)
		last[f.Detector] = len(kept) - 1
	}
	for det, n := range dropped {
		kept[last[det]].Overflow = n
	}
	return kept
}
