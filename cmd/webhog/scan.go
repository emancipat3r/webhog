package main

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/webhog/internal/crawler"
	"github.com/user/webhog/internal/renderer"
	"github.com/user/webhog/internal/scanner"
	"github.com/user/webhog/internal/tech"
	"github.com/user/webhog/internal/ui"
	"github.com/user/webhog/internal/verifier"
)

var scanCmd = &cobra.Command{
	Use:   "scan [url...]",
	Short: "Scan one or more URLs for secrets and interesting endpoints",
	Long: `Scan web pages for exposed secrets, API keys, tokens, and interesting endpoints.

Targets may be given as arguments, via --list <file>, or piped on stdin (one per
line; bare hostnames default to https://). Each target is scanned and crawled
independently and gets its own report.

By default, uses static HTTP fetching. Use --headless to enable browser rendering
for JavaScript-heavy applications.`,
	Args: cobra.ArbitraryArgs,
	RunE: runScan,
}

func init() {
	// Mode flags
	scanCmd.Flags().BoolVar(&cfg.Headless, "headless", false, "use headless browser rendering")
	scanCmd.Flags().DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "page load timeout")

	// Input flags
	scanCmd.Flags().StringVarP(&cfg.ListFile, "list", "l", "", "read targets (one per line) from a file")

	// Crawl flags
	scanCmd.Flags().IntVar(&cfg.MaxDepth, "max-depth", 0, "maximum crawl depth (0 = single URL only)")
	scanCmd.Flags().IntVar(&cfg.MaxPages, "max-pages", 200, "maximum pages to crawl per target (0 = unlimited)")
	scanCmd.Flags().BoolVar(&cfg.SameDomain, "same-domain", true, "restrict the crawl to the seed's registered (apex) domain; set to false to follow off-domain links too")
	scanCmd.Flags().BoolVar(&cfg.Robots, "robots", false, "use robots.txt as an enumeration source: scan its Disallow/Allow paths and Sitemap URLs (does NOT honor crawl restrictions)")

	// Output flags
	scanCmd.Flags().BoolVar(&cfg.JSONOutput, "json", false, "output results as JSON")
	scanCmd.Flags().BoolVar(&cfg.Quiet, "quiet", false, "minimal output")
	scanCmd.Flags().BoolVar(&cfg.PlainOutput, "plain", false, "disable styled output")
	scanCmd.Flags().StringVarP(&cfg.OutputFile, "output", "o", "", "write results to file")

	// Detection flags
	scanCmd.Flags().BoolVar(&cfg.Verify, "verify", false, "validate detected secrets against provider APIs (makes outbound read-only requests using the discovered credentials)")
	scanCmd.Flags().BoolVar(&cfg.IncludeEntropy, "include-entropy", false, "enable entropy-based detection")
	scanCmd.Flags().Float64Var(&cfg.MinEntropy, "min-entropy", 4.5, "minimum entropy threshold")
	scanCmd.Flags().IntVar(&cfg.MinLength, "min-length", 20, "minimum token length for detection")
}

func runScan(cmd *cobra.Command, args []string) error {
	targets, err := collectTargets(args)
	if err != nil {
		return err
	}

	// Renderer and tech detector are created once and reused across targets.
	// Per-page timeouts are applied by the crawler, so the base context carries
	// no overall deadline.
	var r renderer.Renderer
	if cfg.Headless {
		r = renderer.NewHeadlessRenderer(cfg.Timeout)
	} else {
		r = renderer.NewStaticRenderer(cfg.Timeout)
	}
	detector, _ := tech.NewDetector()

	// File outputter (if needed). File output is always plain text and never quiet.
	var fileOutputter *ui.Outputter
	var file *os.File
	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		file = f
		fileOutputter = ui.NewOutputter(true, cfg.JSONOutput, false)
	}

	multi := len(targets) > 1
	var reports []*ui.Report

	for i, target := range targets {
		if multi && !cfg.JSONOutput && !cfg.Quiet {
			fmt.Fprintf(os.Stdout, "\n%s\n[%d/%d] %s\n%s\n",
				strings.Repeat("═", 60), i+1, len(targets), target, strings.Repeat("═", 60))
		}

		report, err := scanOne(r, detector, target)
		if err != nil {
			// In multi-target mode one bad host shouldn't abort the run.
			if !multi {
				return err
			}
			fmt.Fprintf(os.Stderr, "scan failed for %s: %v\n", target, err)
			continue
		}
		reports = append(reports, report)
	}

	if len(reports) == 0 {
		return fmt.Errorf("no targets could be scanned")
	}

	// Write all reports to the output file, if requested.
	if fileOutputter != nil {
		if err := fileOutputter.OutputReports(file, reports); err != nil {
			return fmt.Errorf("writing output file: %w", err)
		}
	}

	// Non-JSON output was streamed per target already; JSON is emitted at the end
	// (a single object for one target, an array for many).
	if cfg.JSONOutput {
		out := ui.NewOutputter(cfg.NoColor || cfg.PlainOutput, true, cfg.Quiet)
		return out.OutputReports(os.Stdout, reports)
	}

	return nil
}

// scanOne crawls and scans a single target, streaming findings live (for
// non-JSON output) and returning the aggregated report.
func scanOne(r renderer.Renderer, detector *tech.Detector, target string) (*ui.Report, error) {
	outputter := ui.NewOutputter(cfg.NoColor || cfg.PlainOutput, cfg.JSONOutput, cfg.Quiet)

	// The crawl frontier is expanded with both <a href> anchors and the
	// endpoints the scanner discovers inside JavaScript/HTML, so additional
	// attack surface (API paths, internal URLs) is fetched and mined too.
	endpointScanner := scanner.NewScanner(cfg.IncludeEntropy, cfg.MinEntropy, cfg.MinLength)
	discoverEndpoints := func(res *renderer.RenderResult) []string {
		return endpointScanner.ExtractEndpoints(res)
	}
	c := crawler.New(r, cfg.MaxDepth, cfg.MaxPages, cfg.SameDomain, cfg.Timeout, discoverEndpoints)

	// Build the seed list. With --robots, robots.txt is mined for paths to scan
	// (Disallow/Allow entries and Sitemap URLs) and added as seeds, so they are
	// enumerated even without deep crawling.
	seeds := []string{target}
	if cfg.Robots {
		robotsTargets := crawler.RobotsTargets(context.Background(), target, &http.Client{Timeout: cfg.Timeout})
		if cfg.Verbose && !cfg.Quiet {
			fmt.Fprintf(os.Stderr, "robots.txt: enumerating %d path(s)\n", len(robotsTargets))
		}
		seeds = append(seeds, robotsTargets...)
	}

	var (
		seedResult   *renderer.RenderResult
		firstErr     error
		pagesCrawled int
		totalJSBlobs int
		techSet      = make(map[string]bool)
	)

	findingsChan := make(chan scanner.Finding)
	go func() {
		defer close(findingsChan)
		s := scanner.NewScanner(cfg.IncludeEntropy, cfg.MinEntropy, cfg.MinLength)

		for page := range c.Crawl(context.Background(), seeds...) {
			if page.Err != nil {
				if firstErr == nil {
					firstErr = page.Err
				}
				if cfg.Verbose && !cfg.Quiet {
					fmt.Fprintf(os.Stderr, "skip %s: %v\n", page.URL, page.Err)
				}
				continue
			}

			pagesCrawled++
			if seedResult == nil {
				seedResult = page.Result
			}
			totalJSBlobs += len(page.Result.JSBlobs)
			if detector != nil {
				for _, t := range detector.Analyze(page.Result.Headers, []byte(page.Result.HTML)) {
					techSet[t] = true
				}
			}
			if cfg.Verbose && !cfg.Quiet {
				fmt.Fprintf(os.Stderr, "[depth %d] %s (HTTP %d, %d JS blobs)\n",
					page.Depth, page.Result.URL, page.Result.Status, len(page.Result.JSBlobs))
			}

			s.ScanStream(page.Result, findingsChan)
		}
	}()

	// Optionally validate secrets against provider APIs before display.
	var outChan <-chan scanner.Finding = findingsChan
	if cfg.Verify {
		if cfg.Verbose && !cfg.Quiet {
			fmt.Fprintln(os.Stderr, "Verifying secrets against provider APIs...")
		}
		outChan = verifyFindings(findingsChan)
	}

	// StreamOutput drains the channel, printing findings progressively (for
	// non-JSON output), and returns the deduplicated set. It returns only after
	// the scan goroutine has closed the channel, so the aggregate counters are
	// safe to read below.
	displayFindings := outputter.StreamOutput(os.Stdout, outChan)

	if pagesCrawled == 0 {
		if firstErr != nil {
			return nil, fmt.Errorf("failed to render page: %w", firstErr)
		}
		return nil, fmt.Errorf("no pages could be scanned")
	}

	report := &ui.Report{
		URL:          seedResult.URL,
		Status:       seedResult.Status,
		PagesCrawled: pagesCrawled,
		JSBlobs:      totalJSBlobs,
		Technologies: sortedKeys(techSet),
		Findings:     displayFindings,
	}

	// For non-JSON output, print this target's summary box now.
	if !cfg.JSONOutput && !cfg.Quiet {
		outputter.PrintSummary(os.Stdout, report)
	}

	return report, nil
}

// collectTargets gathers scan targets from positional args, --list, and (when
// neither is given) stdin. Bare hostnames are upgraded to https://, blank lines
// and #comments are ignored, and duplicates are removed while preserving order.
func collectTargets(args []string) ([]string, error) {
	var raw []string
	raw = append(raw, args...)

	if cfg.ListFile != "" {
		lines, err := readLinesFromFile(cfg.ListFile)
		if err != nil {
			return nil, fmt.Errorf("reading --list file: %w", err)
		}
		raw = append(raw, lines...)
	}

	// Default to stdin only when no targets were given another way and stdin is
	// piped (not an interactive terminal), so the tool doesn't hang waiting.
	if len(raw) == 0 && stdinPiped() {
		lines, err := readLines(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		raw = append(raw, lines...)
	}

	seen := make(map[string]bool)
	var targets []string
	for _, t := range raw {
		t = strings.TrimSpace(t)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if !strings.Contains(t, "://") {
			t = "https://" + t
		}
		if !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets: provide a URL argument, --list <file>, or pipe URLs on stdin")
	}
	return targets, nil
}

func stdinPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice == 0
}

func readLinesFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLines(f)
}

func readLines(r *os.File) ([]string, error) {
	var lines []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

// sortedKeys returns the keys of set in sorted order.
func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// verifyFindings consumes findings and, for secrets that have a registered
// provider verifier, annotates each with its verification status. Results are
// cached per (detector, token) so duplicate matches are only checked once.
func verifyFindings(in <-chan scanner.Finding) <-chan scanner.Finding {
	out := make(chan scanner.Finding)
	go func() {
		defer close(out)
		v := verifier.New(10 * time.Second)
		cache := make(map[string]scanner.Verification)
		ctx := context.Background()

		for f := range in {
			if f.Type == scanner.DetectorSecret && v.CanVerify(f.Detector) {
				key := f.Detector + "|" + f.Token
				status, ok := cache[key]
				if !ok {
					status = v.Verify(ctx, f.Detector, f.Token)
					cache[key] = status
				}
				f.Verification = status
			}
			out <- f
		}
	}()
	return out
}
