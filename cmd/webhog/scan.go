package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/emancipat3r/webhog/internal/crawler"
	"github.com/emancipat3r/webhog/internal/ratelimit"
	"github.com/emancipat3r/webhog/internal/renderer"
	"github.com/emancipat3r/webhog/internal/scanner"
	"github.com/emancipat3r/webhog/internal/tech"
	"github.com/emancipat3r/webhog/internal/ui"
	"github.com/emancipat3r/webhog/internal/verifier"
	"github.com/emancipat3r/webhog/internal/version"
	"github.com/spf13/cobra"
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
	scanCmd.Flags().DurationVar(&cfg.DOMWait, "dom-wait", renderer.DefaultDOMWait, "headless: time to let a page settle after load before reading it (0 = none)")

	// Input flags
	scanCmd.Flags().StringVarP(&cfg.ListFile, "list", "l", "", "read targets (one per line) from a file")

	// Crawl flags
	scanCmd.Flags().IntVar(&cfg.MaxDepth, "max-depth", 0, "maximum crawl depth (0 = single URL only)")
	scanCmd.Flags().IntVar(&cfg.MaxPages, "max-pages", 200, "maximum pages to crawl per target (0 = unlimited)")
	scanCmd.Flags().BoolVar(&cfg.SameDomain, "same-domain", true, "restrict the crawl to the seed's registered (apex) domain; set to false to follow off-domain links too")
	scanCmd.Flags().BoolVar(&cfg.Robots, "robots", false, "use robots.txt as an enumeration source: scan its Disallow/Allow paths and Sitemap URLs (does NOT honor crawl restrictions)")

	// Pacing flags. The limiter is process-wide: it covers every request webhog
	// originates (pages, scripts in static mode, robots.txt, headless
	// navigations) across all workers and targets, so raising concurrency never
	// raises the request rate above the ceiling. Sub-resources the browser
	// loads on its own during a navigation are not individually limited.
	scanCmd.Flags().Float64Var(&cfg.RateLimit, "rate-limit", 0, "maximum requests per second across the whole run (0 = unlimited)")
	scanCmd.Flags().DurationVar(&cfg.Delay, "delay", 0, "minimum time between requests, e.g. 500ms (0 = none)")
	scanCmd.Flags().IntVarP(&cfg.Concurrency, "concurrency", "c", 4, "pages rendered at once within a target")
	scanCmd.Flags().IntVarP(&cfg.Parallel, "parallel", "p", 1, "targets scanned at once (live text output is buffered per target when > 1)")

	// Output flags
	scanCmd.Flags().BoolVar(&cfg.JSONOutput, "json", false, "output results as JSON (one object for a single target, an array for many, written when the run ends)")
	scanCmd.Flags().BoolVar(&cfg.JSONL, "jsonl", false, "output results as JSON Lines: one report per line, written as each target completes")
	scanCmd.Flags().BoolVar(&cfg.Quiet, "quiet", false, "minimal output")
	scanCmd.Flags().BoolVar(&cfg.PlainOutput, "plain", false, "disable styled output")
	scanCmd.Flags().StringVarP(&cfg.OutputFile, "output", "o", "", "write results to file")

	// HTTP identity flags. These apply to every outbound request webhog makes
	// (page fetches, referenced JS, and the headless browser's sub-resources) so
	// recon traffic can be attributed, as some bug-bounty programs require.
	scanCmd.Flags().StringVar(&cfg.UserAgent, "user-agent", "", "User-Agent to send on every request (empty = webhog default)")
	scanCmd.Flags().StringArrayVar(&cfg.Headers, "header", nil, "extra request header as \"Key: Value\"; repeatable")

	// Detection flags
	scanCmd.Flags().BoolVar(&cfg.Verify, "verify", false, "validate detected secrets against provider APIs (makes outbound read-only requests using the discovered credentials)")
	scanCmd.Flags().BoolVar(&cfg.IncludeEntropy, "include-entropy", false, "enable entropy-based detection")
	scanCmd.Flags().Float64Var(&cfg.MinEntropy, "min-entropy", 4.5, "minimum entropy threshold")
	scanCmd.Flags().IntVar(&cfg.MinLength, "min-length", 20, "minimum token length for detection")
}

// limiter is the process-wide request pacer, built from --rate-limit and
// --delay at the start of a scan and shared by every renderer and target.
var limiter *ratelimit.Limiter

func runScan(cmd *cobra.Command, args []string) error {
	targets, err := collectTargets(args)
	if err != nil {
		return err
	}
	limiter = ratelimit.New(cfg.RateLimit, cfg.Delay)

	// Renderer and tech detector are created once and reused across targets.
	// In headless mode that means one Chromium process for the whole run,
	// launched on first use and shut down when the scan ends; each target gets
	// its own incognito context inside it (see scanOne). Per-page timeouts are
	// applied by the crawler, so the base context carries no overall deadline.
	httpCfg := buildHTTPConfig()
	var r renderer.Renderer
	if cfg.Headless {
		hr := renderer.NewHeadlessRenderer(cfg.Timeout, httpCfg).SetDOMWait(cfg.DOMWait)
		defer hr.Close()
		r = hr
	} else {
		r = renderer.NewStaticRenderer(cfg.Timeout, httpCfg)
	}
	detector, _ := tech.NewDetector()

	sink, err := newReportSink()
	if err != nil {
		return err
	}
	defer sink.close()

	multi := len(targets) > 1
	parallel := cfg.Parallel
	if parallel < 1 {
		parallel = 1
	}
	if parallel > len(targets) {
		parallel = len(targets)
	}

	// Targets are scanned by a bounded pool. With one worker, text output
	// streams live exactly as before. With more, each target's text is
	// buffered and flushed whole when it completes, so reports never
	// interleave. Reports go to the sink as they finish in either case.
	var (
		mu                sync.Mutex
		succeeded, failed int
		firstErr          error
		wg                sync.WaitGroup
		sem               = make(chan struct{}, parallel)
	)
	for i, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, target string) {
			defer wg.Done()
			defer func() { <-sem }()

			var w io.Writer = os.Stdout
			var buf *bytes.Buffer
			if parallel > 1 {
				buf = &bytes.Buffer{}
				w = buf
			}
			if multi && !jsonMode() && !cfg.Quiet {
				fmt.Fprintf(w, "\n%s\n[%d/%d] %s\n%s\n",
					strings.Repeat("═", 60), i+1, len(targets), target, strings.Repeat("═", 60))
			}

			report, err := scanOne(w, r, detector, target)
			if err != nil {
				// A failed target still gets a report (with Error set) so the
				// output shows coverage, not just findings. In multi-target
				// mode one bad host shouldn't abort the run.
				fmt.Fprintf(os.Stderr, "scan failed for %s: %v\n", target, err)
				report = &ui.Report{Webhog: version.String(), Seed: target, URL: target, Error: err.Error()}
			}

			mu.Lock()
			defer mu.Unlock()
			if buf != nil {
				_, _ = os.Stdout.Write(buf.Bytes())
			}
			if err != nil {
				failed++
				if firstErr == nil {
					firstErr = err
				}
			} else {
				succeeded++
			}
			if emitErr := sink.emit(report); emitErr != nil && firstErr == nil {
				firstErr = emitErr
			}
		}(i, target)
	}
	wg.Wait()

	if err := sink.finish(); err != nil {
		return err
	}
	if !multi && failed > 0 {
		return firstErr
	}
	if multi && failed > 0 {
		fmt.Fprintf(os.Stderr, "%d of %d targets failed\n", failed, len(targets))
	}
	if succeeded == 0 {
		return fmt.Errorf("no targets could be scanned")
	}
	return nil
}

// jsonMode reports whether stdout carries machine-readable output (--json or
// --jsonl), in which case no live text is streamed.
func jsonMode() bool {
	return cfg.JSONOutput || cfg.JSONL
}

// reportSink routes completed reports to stdout and the optional output file.
//
// Everything that can be written incrementally is: JSON Lines go out one line
// per target the moment it finishes, and the text output file is appended per
// target. Only --json (a single array) has to wait for the end, because the
// array is not valid until it is closed. A run killed part-way therefore
// leaves every completed target on disk in every mode but --json.
type reportSink struct {
	mu   sync.Mutex
	file *os.File

	fileOut   *ui.Outputter // text or JSON view for the file, nil without -o
	stdoutOut *ui.Outputter // JSON view for stdout, nil for text mode

	retained []*ui.Report // --json only: collected for the closing array
	written  int          // reports already appended to the text file
}

func newReportSink() (*reportSink, error) {
	s := &reportSink{}
	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
		s.file = f
		// File output is always plain text and never quiet.
		s.fileOut = ui.NewOutputter(true, jsonMode(), false)
	}
	if jsonMode() {
		s.stdoutOut = ui.NewOutputter(cfg.NoColor || cfg.PlainOutput, true, cfg.Quiet)
	}
	return s, nil
}

// emit records one finished target. Text was already streamed to stdout by
// scanOne, so stdout only needs the machine-readable forms here.
func (s *reportSink) emit(r *ui.Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case cfg.JSONL:
		if err := s.stdoutOut.OutputJSONL(os.Stdout, r); err != nil {
			return err
		}
		if s.file != nil {
			if err := s.fileOut.OutputJSONL(s.file, r); err != nil {
				return fmt.Errorf("writing output file: %w", err)
			}
		}
	case cfg.JSONOutput:
		s.retained = append(s.retained, r)
	default:
		if s.file != nil {
			if s.written > 0 {
				fmt.Fprintln(s.file)
			}
			s.written++
			if err := s.fileOut.Output(s.file, r); err != nil {
				return fmt.Errorf("writing output file: %w", err)
			}
		}
	}
	return nil
}

// finish writes whatever could not be streamed: the --json array.
func (s *reportSink) finish() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !cfg.JSONOutput || len(s.retained) == 0 {
		return nil
	}
	if s.file != nil {
		if err := s.fileOut.OutputReports(s.file, s.retained); err != nil {
			return fmt.Errorf("writing output file: %w", err)
		}
	}
	err := s.stdoutOut.OutputReports(os.Stdout, s.retained)
	s.retained = nil
	return err
}

func (s *reportSink) close() {
	if s.file != nil {
		_ = s.file.Close()
	}
}

// scanOne crawls and scans a single target, streaming findings to w (for
// non-JSON output) and returning the aggregated report.
func scanOne(w io.Writer, r renderer.Renderer, detector *tech.Detector, target string) (*ui.Report, error) {
	outputter := ui.NewOutputter(cfg.NoColor || cfg.PlainOutput, jsonMode(), cfg.Quiet)

	// Isolate this target from the others: a session-capable renderer (the
	// headless one) gets a fresh browser context, so cookies and storage set by
	// one host are never presented to the next.
	if sr, ok := r.(renderer.Sessioner); ok {
		session, err := sr.NewSession()
		if err != nil {
			return nil, fmt.Errorf("starting browser session: %w", err)
		}
		defer session.Close()
		r = session
	}

	// The crawl frontier is expanded with both <a href> anchors and the
	// endpoints the scanner discovers inside JavaScript/HTML, so additional
	// attack surface (API paths, internal URLs) is fetched and mined too.
	endpointScanner := scanner.NewScanner(cfg.IncludeEntropy, cfg.MinEntropy, cfg.MinLength)
	discoverEndpoints := func(res *renderer.RenderResult) []string {
		return endpointScanner.ExtractEndpoints(res)
	}
	c := crawler.New(r, cfg.MaxDepth, cfg.MaxPages, cfg.SameDomain, cfg.Timeout, discoverEndpoints).
		SetConcurrency(cfg.Concurrency)

	// Build the seed list. With --robots, robots.txt is mined for paths to scan
	// (Disallow/Allow entries and Sitemap URLs) and added as seeds, so they are
	// enumerated even without deep crawling.
	seeds := []string{target}
	if cfg.Robots {
		robotsTargets := crawler.RobotsTargets(context.Background(), target, &http.Client{Timeout: cfg.Timeout}, buildHTTPConfig())
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
		totalRefused int
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
			totalRefused += page.Result.Refused()
			if detector != nil {
				for _, t := range detector.Analyze(page.Result.Headers, []byte(page.Result.HTML)) {
					techSet[t] = true
				}
			}
			if cfg.Verbose && !cfg.Quiet {
				fmt.Fprintf(os.Stderr, "[depth %d] %s (HTTP %d, %d JS blobs, %d refused)\n",
					page.Depth, page.Result.URL, page.Result.Status, len(page.Result.JSBlobs), page.Result.Refused())
				for _, re := range page.Result.Errors {
					fmt.Fprintf(os.Stderr, "  could not fetch %s: %s\n", re.URL, re.Err)
				}
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
	displayFindings := outputter.StreamOutput(w, outChan)

	if pagesCrawled == 0 {
		if firstErr != nil {
			return nil, fmt.Errorf("failed to render page: %w", firstErr)
		}
		return nil, fmt.Errorf("no pages could be scanned")
	}

	// A seed that lands on another registered domain (an SSO front, say) is
	// still fetched, because that is where the seed leads, but the crawler
	// never follows the landing page's links. Record the boundary crossing:
	// it is a real observation about the target and it explains why the
	// report's URL names a host the caller did not ask for.
	offScope := cfg.SameDomain && !crawler.SameScope(target, seedResult.URL)
	if offScope && !cfg.Quiet {
		fmt.Fprintf(os.Stderr, "%s redirected off scope to %s: landing page scanned, its links not crawled\n", target, seedResult.URL)
	}

	report := &ui.Report{
		Webhog:             version.String(),
		Seed:               target,
		URL:                seedResult.URL,
		RedirectedOffScope: offScope,
		Status:             seedResult.Status,
		PagesCrawled:       pagesCrawled,
		JSBlobs:            totalJSBlobs,
		JSRefused:          totalRefused,
		Technologies:       sortedKeys(techSet),
		Findings:           displayFindings,
	}

	// For non-JSON output, print this target's summary box now.
	if !jsonMode() && !cfg.Quiet {
		outputter.PrintSummary(w, report)
	}

	return report, nil
}

// buildHTTPConfig assembles the per-request identity (custom User-Agent and
// extra headers) applied to every outbound request. Each --header is "Key:
// Value", split on the first colon; malformed entries (no colon or an empty key)
// are reported and skipped rather than aborting the scan.
func buildHTTPConfig() renderer.HTTPConfig {
	hc := renderer.HTTPConfig{
		UserAgent: strings.TrimSpace(cfg.UserAgent),
		Limiter:   limiter,
	}
	for _, raw := range cfg.Headers {
		key, value, found := strings.Cut(raw, ":")
		key = strings.TrimSpace(key)
		if !found || key == "" {
			fmt.Fprintf(os.Stderr, "ignoring malformed --header %q (expected \"Key: Value\")\n", raw)
			continue
		}
		hc.Headers = append(hc.Headers, renderer.Header{Key: key, Value: strings.TrimSpace(value)})
	}
	return hc
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
