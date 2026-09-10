package main

import (
	"github.com/emancipat3r/webhog/internal/config"
	"github.com/emancipat3r/webhog/internal/version"
	"github.com/spf13/cobra"
)

var cfg = &config.Config{}

var rootCmd = &cobra.Command{
	Use:   "webhog",
	Short: "A headless web secret scanner",
	Long: `Webhog is a CLI tool that scans web pages for secrets, API keys,
tokens, and interesting endpoints. It supports both static (HTTP-only)
and headless browser modes for JavaScript-heavy applications.`,
	Version: version.String(),
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&cfg.NoColor, "no-color", false, "disable colored output")
	rootCmd.PersistentFlags().StringVar(&cfg.ConfigFile, "config", "", "config file path")

	// Add subcommands
	rootCmd.AddCommand(scanCmd)
}
