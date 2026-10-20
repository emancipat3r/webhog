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
	// Keyword is a lower-case literal that must appear in a line before Re is
	// tried against it. It is a cheap prefilter for large bundles; an empty
	// Keyword means the regex always runs.
	Keyword string
	// Public marks a credential shape that is meant to be served to browsers
	// (a Stripe publishable key, a Datadog client token, a Sentry DSN). The
	// match is still reported, so a consumer sees what the page ships, but it
	// is labelled so nobody triages it as a leak.
	Public bool
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
	// Public is true when the detector describes a credential that is public
	// by design (see Detector.Public).
	Public bool `json:"public,omitempty"`
	// ThirdParty is true when the resource in Path is served from a registered
	// domain other than the scan target's: a tag manager, an analytics
	// vendor, a CDN-hosted library. Secrets in such files belong to whoever
	// publishes the file, not to the target.
	ThirdParty bool `json:"third_party,omitempty"`
	// Details carries facts derived from the token itself without any
	// network traffic: a JWT's issuer and expiry, the AWS account an access
	// key belongs to, the mode of a Stripe key. Verifiers add what the
	// provider said (scopes, account identity) under the same map.
	Details map[string]string `json:"details,omitempty"`
	// Overflow is set on the last finding kept for a (file, detector) pair
	// when the generic cap dropped further matches in the same file; it is
	// the number of matches not reported.
	Overflow int `json:"overflow,omitempty"`
}
