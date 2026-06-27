package scanner

import "regexp"

// DetectorType categorizes the type of finding
type DetectorType string

const (
	DetectorSecret   DetectorType = "secret"
	DetectorEndpoint DetectorType = "endpoint"
	DetectorConfig   DetectorType = "config"
	DetectorGeneric  DetectorType = "generic"
)

// Verification is the result of attempting to validate a secret against its
// provider's API (only populated when --verify is enabled).
type Verification string

const (
	VerifyNone    Verification = ""        // verification not attempted
	VerifyValid   Verification = "valid"   // provider confirmed the credential is active
	VerifyInvalid Verification = "invalid" // provider rejected the credential
	VerifyUnknown Verification = "unknown" // a verifier exists but couldn't determine status
)

// Detector represents a pattern-based detector
type Detector struct {
	Name string
	Type DetectorType
	Re   *regexp.Regexp
}

// Finding represents a discovered secret or endpoint
type Finding struct {
	Detector     string       `json:"detector"`
	Type         DetectorType `json:"type"`
	Path         string       `json:"path"`                   // JS file or inline location
	LineNum      int          `json:"line"`                   // Line number in the blob
	Snippet      string       `json:"snippet"`                // Context around the match
	Token        string       `json:"token"`                  // The actual match
	Verification Verification `json:"verification,omitempty"` // Provider validation result (--verify)
	// LoadedFrom is the URL of the HTML page that referenced the resource named
	// in Path. It is set when the match lives in an external JS file pulled in by
	// a page, giving downstream consumers the provenance of the secret. It is nil
	// (serialized as null) when the match is in the page's own HTML/inline body,
	// because Path already is that page.
	LoadedFrom *string `json:"loaded_from"`
}
