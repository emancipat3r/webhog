package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/webhog/internal/renderer"
	"github.com/user/webhog/internal/scanner"
	"github.com/user/webhog/internal/ui"
)

var scanCmd = &cobra.Command{
	Use:   "scan [url]",
	Short: "Scan a URL for secrets and interesting endpoints",
	Long: `Scan a web page for exposed secrets, API keys, tokens, and interesting endpoints.

By default, uses static HTTP fetching. Use --headless to enable browser rendering
for JavaScript-heavy applications.`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	// Mode flags
	scanCmd.Flags().BoolVar(&cfg.Headless, "headless", false, "use headless browser rendering")
	scanCmd.Flags().DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "page load timeout")

	// Crawl flags
	scanCmd.Flags().IntVar(&cfg.MaxDepth, "max-depth", 0, "maximum crawl depth (0 = single URL only)")
	scanCmd.Flags().BoolVar(&cfg.SameDomain, "same-domain", false, "only follow links on same domain")

	// Output flags
	scanCmd.Flags().BoolVar(&cfg.JSONOutput, "json", false, "output results as JSON")
	scanCmd.Flags().BoolVar(&cfg.Quiet, "quiet", false, "minimal output")
	scanCmd.Flags().BoolVar(&cfg.PlainOutput, "plain", false, "disable styled output")

	// Detection flags
	scanCmd.Flags().BoolVar(&cfg.IncludeEntropy, "include-entropy", false, "enable entropy-based detection")
	scanCmd.Flags().Float64Var(&cfg.MinEntropy, "min-entropy", 4.5, "minimum entropy threshold")
	scanCmd.Flags().IntVar(&cfg.MinLength, "min-length", 20, "minimum token length for detection")
}

func runScan(cmd *cobra.Command, args []string) error {
	targetURL := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	// Select renderer
	var r renderer.Renderer
	if cfg.Headless {
		r = renderer.NewHeadlessRenderer(cfg.Timeout)
	} else {
		r = renderer.NewStaticRenderer(cfg.Timeout)
	}

	// Render the page
	if cfg.Verbose && !cfg.Quiet {
		fmt.Fprintf(os.Stderr, "Rendering %s...\n", targetURL)
	}

	result, err := r.Render(ctx, targetURL)
	if err != nil {
		return fmt.Errorf("failed to render page: %w", err)
	}

	if cfg.Verbose && !cfg.Quiet {
		fmt.Fprintf(os.Stderr, "Found %d JS blobs\n", len(result.JSBlobs))
	}

	// Scan for secrets
	s := scanner.NewScanner(cfg.IncludeEntropy, cfg.MinEntropy, cfg.MinLength)
	findings := s.Scan(result)

	// Output results
	outputter := ui.NewOutputter(cfg.NoColor || cfg.PlainOutput, cfg.JSONOutput, cfg.Quiet)
	return outputter.Output(os.Stdout, findings, result)
}
