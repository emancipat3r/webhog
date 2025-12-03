package config

import "time"

// Config holds all configuration for the application
type Config struct {
	// Global flags
	Verbose    bool
	NoColor    bool
	ConfigFile string

	// Scan flags
	Headless      bool
	Timeout       time.Duration
	MaxDepth      int
	SameDomain    bool
	JSONOutput    bool
	Quiet         bool
	PlainOutput   bool
	IncludeEntropy bool
	MinEntropy     float64
	MinLength      int
}

// NewConfig returns a Config with sensible defaults
func NewConfig() *Config {
	return &Config{
		Timeout:    30 * time.Second,
		MaxDepth:   0,
		MinEntropy: 4.5,
		MinLength:  20,
	}
}
