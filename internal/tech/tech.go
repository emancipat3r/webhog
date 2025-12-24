package tech

import (
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// Detector is a wrapper around wappalyzergo
type Detector struct {
	wappalyzer *wappalyzer.Wappalyze
}

// NewDetector creates a new technology detector
func NewDetector() (*Detector, error) {
	w, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}
	return &Detector{wappalyzer: w}, nil
}

// Analyze identifies technologies from headers and body
func (d *Detector) Analyze(headers map[string][]string, body []byte) []string {
	fingerprints := d.wappalyzer.Fingerprint(headers, body)

	var technologies []string
	for name := range fingerprints {
		technologies = append(technologies, name)
	}

	return technologies
}
