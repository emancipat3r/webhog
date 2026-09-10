package config

import "time"

// Config holds all configuration for the application
type Config struct {
	// Global flags
	Verbose    bool
	NoColor    bool
	ConfigFile string

	// Scan flags
	Headless       bool
	Timeout        time.Duration
	DOMWait        time.Duration // headless: settle time after load
	ListFile       string
	MaxDepth       int
	MaxPages       int
	SameDomain     bool
	Robots         bool
	JSONOutput     bool
	JSONL          bool // one JSON report per line, streamed per target
	Quiet          bool
	PlainOutput    bool
	OutputFile     string
	IncludeEntropy bool
	MinEntropy     float64
	MinLength      int
	Verify         bool

	// Pacing and parallelism.
	RateLimit   float64       // max requests per second webhog originates (0 = unlimited)
	Delay       time.Duration // minimum spacing between requests (0 = none)
	Concurrency int           // pages rendered at once within a target
	Parallel    int           // targets scanned at once

	// Outbound HTTP identity, applied to every request webhog makes.
	UserAgent string   // custom User-Agent (empty = default)
	Headers   []string // extra request headers, each "Key: Value"
}

// NewConfig returns a Config with sensible defaults
func NewConfig() *Config {
	return &Config{
		Timeout:     30 * time.Second,
		MaxDepth:    0,
		MaxPages:    200,
		SameDomain:  true,
		MinEntropy:  4.5,
		MinLength:   20,
		Concurrency: 4,
		Parallel:    1,
	}
}
