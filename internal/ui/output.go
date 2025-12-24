package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/user/webhog/internal/renderer"
	"github.com/user/webhog/internal/scanner"
)

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
		fmt.Fprintf(w, "[%s] %s:%d %s: %s\n", f.Detector, f.Path, f.LineNum, label, f.Token)
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

	fmt.Fprintf(w, "\n%s %s\n", style.Render("▸"), f.Detector)
	fmt.Fprintf(w, "  %s %s:%d\n", pathStyle.Render("Location:"), f.Path, f.LineNum)
	fmt.Fprintf(w, "  %s %s\n", tokenStyle.Render(label+":"), f.Token)
	if f.Snippet != "" {
		fmt.Fprintf(w, "  %s %s\n", snippetStyle.Render("Context:"), f.Snippet)
	}
}

// Output writes the findings to the given writer
func (o *Outputter) Output(w io.Writer, findings []scanner.Finding, result *renderer.RenderResult, technologies []string) error {
	if o.jsonOutput {
		return o.outputJSON(w, findings, result, technologies)
	}

	if o.noStyle {
		return o.outputPlain(w, findings, result, technologies)
	}

	return o.outputStyled(w, findings, result, technologies)
}

// outputJSON outputs findings as JSON
func (o *Outputter) outputJSON(w io.Writer, findings []scanner.Finding, result *renderer.RenderResult, technologies []string) error {
	output := map[string]interface{}{
		"url":          result.URL,
		"js_blobs":     len(result.JSBlobs),
		"technologies": technologies,
		"findings":     findings,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// outputPlain outputs findings in plain text
func (o *Outputter) outputPlain(w io.Writer, findings []scanner.Finding, result *renderer.RenderResult, technologies []string) error {
	if !o.quiet {
		fmt.Fprintf(w, "Scanned: %s\n", result.URL)
		fmt.Fprintf(w, "Technologies: %s\n", strings.Join(technologies, ", "))
		fmt.Fprintf(w, "JS Blobs: %d\n", len(result.JSBlobs))
		fmt.Fprintf(w, "Findings: %d\n\n", len(findings))
	}
	// ... (rest of plain output logic omitted for brevity, logic remains same)
	if len(findings) == 0 {
		if !o.quiet {
			fmt.Fprintln(w, "No secrets or interesting endpoints found.")
		}
		return nil
	}
	// ...
	// Group findings by type
	byType := groupByType(findings)
	// ...
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
			fmt.Fprintf(w, "\n[%s] %s:%d\n", f.Detector, f.Path, f.LineNum)
			fmt.Fprintf(w, "%s: %s\n", label, f.Token)
			if f.Snippet != "" {
				fmt.Fprintf(w, "Context: %s\n", f.Snippet)
			}
		}
	}

	return nil
}

// outputStyled outputs findings with styled formatting
func (o *Outputter) outputStyled(w io.Writer, findings []scanner.Finding, result *renderer.RenderResult, technologies []string) error {
	// Title
	fmt.Fprintln(w, titleStyle.Render("Webhog Scan Results"))

	// Summary
	if !o.quiet {
		summary := o.buildSummary(result, findings, technologies)
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
func (o *Outputter) PrintSummary(w io.Writer, findings []scanner.Finding, result *renderer.RenderResult, technologies []string) {
	summary := o.buildSummary(result, findings, technologies)

	if o.noStyle {
		fmt.Fprintln(w, summary)
	} else {
		fmt.Fprintln(w, summaryBoxStyle.Render(summary))
	}
}

// buildSummary creates a summary string
func (o *Outputter) buildSummary(result *renderer.RenderResult, findings []scanner.Finding, technologies []string) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("URL: %s\n", result.URL))
	if len(technologies) > 0 {
		b.WriteString(fmt.Sprintf("Tech: %s\n", strings.Join(technologies, ", ")))
	}
	b.WriteString(fmt.Sprintf("JS Blobs: %d\n", len(result.JSBlobs)))
	b.WriteString(fmt.Sprintf("Total Findings: %d\n\n", len(findings)))

	// Count by type
	byType := groupByType(findings)
	b.WriteString("By Type:\n")
	b.WriteString(fmt.Sprintf("  Secrets:       %d\n", len(byType[scanner.DetectorSecret])))
	b.WriteString(fmt.Sprintf("  Configuration: %d\n", len(byType[scanner.DetectorConfig])))
	b.WriteString(fmt.Sprintf("  Endpoints:     %d\n", len(byType[scanner.DetectorEndpoint])))
	b.WriteString(fmt.Sprintf("  Generic:       %d\n", len(byType[scanner.DetectorGeneric])))

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
		fmt.Fprintf(w, "\n%s %s\n", style.Render("▸"), f.Detector)
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

// groupByType groups findings by their detector type
func groupByType(findings []scanner.Finding) map[scanner.DetectorType][]scanner.Finding {
	result := make(map[scanner.DetectorType][]scanner.Finding)

	for _, f := range findings {
		result[f.Type] = append(result[f.Type], f)
	}

	return result
}
