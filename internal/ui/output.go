package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/user/webhog/internal/scanner"
)

// Report is the aggregate result of a scan (one or many pages) ready for
// display. For a single-page scan PagesCrawled is 1.
type Report struct {
	URL          string            `json:"url"`           // seed URL
	Status       int               `json:"status"`        // seed HTTP status (0 if unknown)
	PagesCrawled int               `json:"pages_crawled"` // number of pages successfully scanned
	JSBlobs      int               `json:"js_blobs"`      // total JS blobs across all pages
	Technologies []string          `json:"technologies"`  // union of detected technologies
	Findings     []scanner.Finding `json:"findings"`      // deduplicated findings
}

// Outputter handles formatting and displaying results
type Outputter struct {
	noStyle    bool
	jsonOutput bool
	quiet      bool
	seen       map[string]bool // Track seen findings to avoid duplicate output during streaming
}

// NewOutputter creates a new outputter
func NewOutputter(noStyle, jsonOutput, quiet bool) *Outputter {
	return &Outputter{
		noStyle:    noStyle,
		jsonOutput: jsonOutput,
		quiet:      quiet,
		seen:       make(map[string]bool),
	}
}

// StreamOutput reads findings from a channel and prints them progressively
func (o *Outputter) StreamOutput(w io.Writer, findingsChan <-chan scanner.Finding) []scanner.Finding {
	var allFindings []scanner.Finding

	// Print header
	if !o.quiet && !o.jsonOutput {
		fmt.Fprintln(w, titleStyle.Render("Webhog Scan Results (Streaming)"))
		fmt.Fprintln(w, strings.Repeat("─", 60))
	}

	for f := range findingsChan {
		// Deduplicate for output stream
		key := f.Detector + "|" + f.Path + "|" + f.Token
		if o.seen[key] {
			continue
		}
		o.seen[key] = true
		allFindings = append(allFindings, f)

		o.PrintFinding(w, f)
	}

	return allFindings
}

// PrintFinding prints a single finding immediately
func (o *Outputter) PrintFinding(w io.Writer, f scanner.Finding) {
	if o.quiet {
		return
	}

	if o.jsonOutput {
		// For JSON stream, we might want NDJSON or just suppress intermediate output?
		// For now, let's just NOT print intermediate JSON to avoid broken JSON array.
		return
	}

	if o.noStyle {
		label := o.getLabelForFinding(f)
		fmt.Fprintf(w, "[%s] %s:%d %s: %s", f.Detector, f.Path, f.LineNum, label, f.Token)
		if tag := o.verificationTag(f); tag != "" {
			fmt.Fprintf(w, " %s", tag)
		}
		fmt.Fprintln(w)
		return
	}

	// Styled output
	var style lipgloss.Style
	switch f.Type {
	case scanner.DetectorSecret:
		style = secretStyle
	case scanner.DetectorConfig:
		style = configStyle
	case scanner.DetectorEndpoint:
		style = endpointStyle
	default:
		style = genericStyle
	}

	label := o.getLabelForFinding(f)

	fmt.Fprintf(w, "\n%s %s", style.Render("▸"), f.Detector)
	if tag := o.verificationTag(f); tag != "" {
		fmt.Fprintf(w, "  %s", tag)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s %s:%d\n", pathStyle.Render("Location:"), f.Path, f.LineNum)
	fmt.Fprintf(w, "  %s %s\n", tokenStyle.Render(label+":"), f.Token)
	if f.Snippet != "" {
		fmt.Fprintf(w, "  %s %s\n", snippetStyle.Render("Context:"), f.Snippet)
	}
}

// OutputReports writes one or more reports. For JSON, a single target is
// emitted as one object (back-compatible) and multiple targets as an array. For
// text, reports are written one after another.
func (o *Outputter) OutputReports(w io.Writer, reports []*Report) error {
	if o.jsonOutput {
		if len(reports) == 1 {
			return o.outputJSON(w, reports[0])
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(reports)
	}

	for i, report := range reports {
		if i > 0 {
			fmt.Fprintln(w)
		}
		if err := o.Output(w, report); err != nil {
			return err
		}
	}
	return nil
}

// Output writes the report to the given writer
func (o *Outputter) Output(w io.Writer, report *Report) error {
	if o.jsonOutput {
		return o.outputJSON(w, report)
	}

	if o.noStyle {
		return o.outputPlain(w, report)
	}

	return o.outputStyled(w, report)
}

// outputJSON outputs the report as JSON
func (o *Outputter) outputJSON(w io.Writer, report *Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// outputPlain outputs findings in plain text
func (o *Outputter) outputPlain(w io.Writer, report *Report) error {
	findings := report.Findings
	if !o.quiet {
		fmt.Fprintf(w, "Scanned: %s\n", report.URL)
		if report.Status > 0 {
			fmt.Fprintf(w, "Status: %d\n", report.Status)
		}
		if report.PagesCrawled > 1 {
			fmt.Fprintf(w, "Pages Crawled: %d\n", report.PagesCrawled)
		}
		fmt.Fprintf(w, "Technologies: %s\n", strings.Join(report.Technologies, ", "))
		fmt.Fprintf(w, "JS Blobs: %d\n", report.JSBlobs)
		fmt.Fprintf(w, "Findings: %d\n\n", len(findings))
	}
	if len(findings) == 0 {
		if !o.quiet {
			fmt.Fprintln(w, "No secrets or interesting endpoints found.")
		}
		return nil
	}
	byType := groupByType(findings)
	for _, fType := range []scanner.DetectorType{
		scanner.DetectorSecret,
		scanner.DetectorConfig,
		scanner.DetectorEndpoint,
		scanner.DetectorGeneric,
	} {
		items := byType[fType]
		if len(items) == 0 {
			continue
		}

		fmt.Fprintf(w, "\n%s (%d)\n", strings.ToUpper(string(fType)), len(items))
		fmt.Fprintln(w, strings.Repeat("-", 40))

		for _, f := range items {
			label := o.getLabelForFinding(f)
			fmt.Fprintf(w, "\n[%s] %s:%d", f.Detector, f.Path, f.LineNum)
			if tag := o.verificationTag(f); tag != "" {
				fmt.Fprintf(w, " %s", tag)
			}
			fmt.Fprintf(w, "\n%s: %s\n", label, f.Token)
			if f.Snippet != "" {
				fmt.Fprintf(w, "Context: %s\n", f.Snippet)
			}
		}
	}

	return nil
}

// outputStyled outputs findings with styled formatting
func (o *Outputter) outputStyled(w io.Writer, report *Report) error {
	findings := report.Findings

	// Title
	fmt.Fprintln(w, titleStyle.Render("Webhog Scan Results"))

	// Summary
	if !o.quiet {
		summary := o.buildSummary(report)
		fmt.Fprintln(w, summaryBoxStyle.Render(summary))
	}

	if len(findings) == 0 {
		if !o.quiet {
			fmt.Fprintln(w, "No secrets or interesting endpoints found.")
		}
		return nil
	}

	// Group findings by type
	byType := groupByType(findings)

	// Output each type
	o.outputTypeSection(w, "SECRETS", scanner.DetectorSecret, byType[scanner.DetectorSecret], secretStyle)
	o.outputTypeSection(w, "CONFIGURATION", scanner.DetectorConfig, byType[scanner.DetectorConfig], configStyle)
	o.outputTypeSection(w, "ENDPOINTS", scanner.DetectorEndpoint, byType[scanner.DetectorEndpoint], endpointStyle)
	o.outputTypeSection(w, "GENERIC", scanner.DetectorGeneric, byType[scanner.DetectorGeneric], genericStyle)

	return nil
}

// PrintSummary prints just the summary box
func (o *Outputter) PrintSummary(w io.Writer, report *Report) {
	summary := o.buildSummary(report)

	if o.noStyle {
		fmt.Fprintln(w, summary)
	} else {
		fmt.Fprintln(w, summaryBoxStyle.Render(summary))
	}
}

// buildSummary creates a summary string
func (o *Outputter) buildSummary(report *Report) string {
	findings := report.Findings
	var b strings.Builder

	b.WriteString(fmt.Sprintf("URL: %s\n", report.URL))
	if report.Status > 0 {
		b.WriteString(fmt.Sprintf("Status: %d\n", report.Status))
	}
	if report.PagesCrawled > 1 {
		b.WriteString(fmt.Sprintf("Pages Crawled: %d\n", report.PagesCrawled))
	}
	if len(report.Technologies) > 0 {
		b.WriteString(fmt.Sprintf("Tech: %s\n", strings.Join(report.Technologies, ", ")))
	}
	b.WriteString(fmt.Sprintf("JS Blobs: %d\n", report.JSBlobs))
	b.WriteString(fmt.Sprintf("Total Findings: %d\n\n", len(findings)))

	// Count by type
	byType := groupByType(findings)
	b.WriteString("By Type:\n")
	b.WriteString(fmt.Sprintf("  Secrets:       %d\n", len(byType[scanner.DetectorSecret])))
	b.WriteString(fmt.Sprintf("  Configuration: %d\n", len(byType[scanner.DetectorConfig])))
	b.WriteString(fmt.Sprintf("  Endpoints:     %d\n", len(byType[scanner.DetectorEndpoint])))
	b.WriteString(fmt.Sprintf("  Generic:       %d\n", len(byType[scanner.DetectorGeneric])))

	// Verification summary (only when --verify attempted something).
	var verified, active int
	for _, f := range findings {
		if f.Verification == scanner.VerifyNone {
			continue
		}
		verified++
		if f.Verification == scanner.VerifyValid {
			active++
		}
	}
	if verified > 0 {
		b.WriteString(fmt.Sprintf("\nVerified Active: %d of %d checked\n", active, verified))
	}

	return b.String()
}

// outputTypeSection outputs a section for a specific finding type
func (o *Outputter) outputTypeSection(w io.Writer, title string, fType scanner.DetectorType, findings []scanner.Finding, style lipgloss.Style) {
	if len(findings) == 0 {
		return
	}

	fmt.Fprintf(w, "\n%s\n", style.Render(title))
	fmt.Fprintln(w, strings.Repeat("─", 60))

	for _, f := range findings {
		label := o.getLabelForFinding(f)
		fmt.Fprintf(w, "\n%s %s", style.Render("▸"), f.Detector)
		if tag := o.verificationTag(f); tag != "" {
			fmt.Fprintf(w, "  %s", tag)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s %s:%d\n", pathStyle.Render("Location:"), f.Path, f.LineNum)
		fmt.Fprintf(w, "  %s %s\n", tokenStyle.Render(label+":"), f.Token)
		if f.Snippet != "" {
			fmt.Fprintf(w, "  %s %s\n", snippetStyle.Render("Context:"), f.Snippet)
		}
	}

	fmt.Fprintln(w)
}

// getLabelForFinding returns the appropriate label for a finding (Token vs URL)
func (o *Outputter) getLabelForFinding(f scanner.Finding) string {
	if f.Type == scanner.DetectorEndpoint {
		return "URL"
	}
	return "Secret"
}

// verificationTag returns a short, possibly-styled tag describing a finding's
// verification status, or an empty string when verification wasn't attempted.
func (o *Outputter) verificationTag(f scanner.Finding) string {
	switch f.Verification {
	case scanner.VerifyValid:
		if o.noStyle {
			return "[VERIFIED ACTIVE]"
		}
		return verifiedValidStyle.Render("VERIFIED ACTIVE")
	case scanner.VerifyInvalid:
		if o.noStyle {
			return "[inactive]"
		}
		return verifiedInvalidStyle.Render("inactive")
	case scanner.VerifyUnknown:
		if o.noStyle {
			return "[unverified]"
		}
		return verifiedUnknownStyle.Render("unverified")
	default:
		return ""
	}
}

// groupByType groups findings by their detector type
func groupByType(findings []scanner.Finding) map[scanner.DetectorType][]scanner.Finding {
	result := make(map[scanner.DetectorType][]scanner.Finding)

	for _, f := range findings {
		result[f.Type] = append(result[f.Type], f)
	}

	return result
}
