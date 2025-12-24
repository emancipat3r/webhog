package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/webhog/internal/renderer"
	"github.com/user/webhog/internal/scanner"
	"github.com/user/webhog/internal/tech"
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
	scanCmd.Flags().StringVarP(&cfg.OutputFile, "output", "o", "", "write results to file")

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

	// Detect technologies
	var technologies []string
	d, err := tech.NewDetector()
	if err == nil {
		technologies = d.Analyze(result.Headers, []byte(result.HTML))
	}

	// Outputter
	outputter := ui.NewOutputter(cfg.NoColor || cfg.PlainOutput, cfg.JSONOutput, cfg.Quiet)

	// File outputter (if needed)
	var fileOutputter *ui.Outputter
	var file *os.File
	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		file = f
		// Force plain text and no quiet for file output
		fileOutputter = ui.NewOutputter(true, cfg.JSONOutput, false)
	}

	// Findings channel
	findingsChan := make(chan scanner.Finding)

	// Start scanning in a goroutine
	go func() {
		defer close(findingsChan)
		s := scanner.NewScanner(cfg.IncludeEntropy, cfg.MinEntropy, cfg.MinLength)
		s.ScanStream(result, findingsChan)
	}()

	// Stream results
	// We need to intercept the stream to write to file as well

	// Print header for file
	if fileOutputter != nil && !cfg.JSONOutput {
		fmt.Fprintf(file, "Webhog Scan Results\n")
		fmt.Fprintf(file, "===================\n\n")
	}

	// Since ui.StreamOutput sucks the channel dry, we can't easily tee it
	// without modifying UI or manually consuming here.
	// Manual consumption is safer to control both outputs.

	displayFindings := outputter.StreamOutput(os.Stdout, findingsChan)

	// After streaming finishes, we have all findings in displayFindings.
	// Note: StreamOutput already handles deduplication internally for display options.
	// For the file, we can just dump displayFindings at the end if we don't care about
	// strict streaming *to the file*. Streaming to file is nice but dumping at end is easier.
	// Wait, user asked: "write output ... while also maintaining current printing output functionality"
	//
	// Writing to file at the end is fine.

	if fileOutputter != nil {
		// Re-output everything to file
		if cfg.JSONOutput {
			fileOutputter.Output(file, displayFindings, result, technologies)
		} else {
			fileOutputter.Output(file, displayFindings, result, technologies)
		}
	}

	if cfg.JSONOutput {
		return outputter.Output(os.Stdout, displayFindings, result, technologies)
	}

	// For normal output, print the summary box at the end
	if !cfg.Quiet {
		outputter.PrintSummary(os.Stdout, displayFindings, result, technologies)
	}

	return nil
}
