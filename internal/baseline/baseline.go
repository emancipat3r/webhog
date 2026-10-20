// Package baseline compares a scan against an earlier one, so a repeated
// scan of the same targets reports what changed: findings not seen before
// and scripts that are new, altered or gone.
package baseline

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/emancipat3r/webhog/internal/renderer"
	"github.com/emancipat3r/webhog/internal/ui"
)

// Baseline indexes earlier reports by the registered domain of their seed,
// so a target that moved between hostnames of one program still compares.
type Baseline struct {
	findings map[string]map[string]bool   // domain -> detector|token
	scripts  map[string]map[string]string // domain -> path -> sha256
	reports  int
}

// Load reads a previous run's output: a single report object, a --json
// array, or --jsonl lines.
func Load(path string) (*Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads reports from r in any of webhog's output forms.
func Parse(r io.Reader) (*Baseline, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	b := &Baseline{findings: map[string]map[string]bool{}, scripts: map[string]map[string]string{}}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return b, nil
	}
	var reports []*ui.Report
	switch trimmed[0] {
	case '[':
		if err := json.Unmarshal(trimmed, &reports); err != nil {
			return nil, fmt.Errorf("baseline is not a report array: %w", err)
		}
	default:
		sc := bufio.NewScanner(bytes.NewReader(trimmed))
		sc.Buffer(make([]byte, 0, 1<<20), 256<<20)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var rep ui.Report
			if err := json.Unmarshal(line, &rep); err != nil {
				// Not JSON Lines: try the whole thing as one object.
				var one ui.Report
				if err2 := json.Unmarshal(trimmed, &one); err2 != nil {
					return nil, fmt.Errorf("baseline is not a report, array or JSON Lines: %w", err)
				}
				reports = []*ui.Report{&one}
				break
			}
			reports = append(reports, &rep)
		}
	}
	for _, rep := range reports {
		b.add(rep)
	}
	return b, nil
}

func (b *Baseline) add(rep *ui.Report) {
	if rep == nil {
		return
	}
	b.reports++
	domain := renderer.RegisteredDomain(rep.Seed)
	if b.findings[domain] == nil {
		b.findings[domain] = map[string]bool{}
		b.scripts[domain] = map[string]string{}
	}
	for _, f := range rep.Findings {
		b.findings[domain][f.Detector+"|"+f.Token] = true
	}
	for _, s := range rep.Scripts {
		b.scripts[domain][s.Path] = s.SHA256
	}
}

// Reports returns how many reports the baseline holds.
func (b *Baseline) Reports() int { return b.reports }

// HasFinding reports whether the baseline saw this detector and token for
// the target's registered domain.
func (b *Baseline) HasFinding(seed, detector, token string) bool {
	return b.findings[renderer.RegisteredDomain(seed)][detector+"|"+token]
}

// Known reports whether the baseline holds any report for the seed's
// registered domain, so a first scan of a new target is not reported as
// all new.
func (b *Baseline) Known(seed string) bool {
	_, ok := b.findings[renderer.RegisteredDomain(seed)]
	return ok
}

// ScriptChanges compares the current script set against the baseline's.
func (b *Baseline) ScriptChanges(seed string, current []ui.ScriptRecord) ui.ScriptChanges {
	prev := b.scripts[renderer.RegisteredDomain(seed)]
	var ch ui.ScriptChanges
	seen := map[string]bool{}
	for _, s := range current {
		seen[s.Path] = true
		old, ok := prev[s.Path]
		switch {
		case !ok:
			ch.Added++
		case old != s.SHA256:
			ch.Changed++
		}
	}
	for p := range prev {
		if !seen[p] {
			ch.Removed++
		}
	}
	return ch
}
