package baseline

import (
	"strings"
	"testing"

	"github.com/emancipat3r/webhog/internal/scanner"
	"github.com/emancipat3r/webhog/internal/ui"
)

const jsonl = `{"seed":"https://www.example.com","findings":[{"detector":"Google API Key","token":"AIza-one"}],"scripts":[{"path":"https://www.example.com/a.js","sha256":"aaa"},{"path":"https://www.example.com/gone.js","sha256":"ggg"}]}
{"seed":"https://other.test","findings":[{"detector":"JWT Token","token":"eyJ.x.y"}]}
`

func TestParseAcceptsAllThreeShapes(t *testing.T) {
	one := strings.Split(jsonl, "\n")[0]
	for name, in := range map[string]string{
		"jsonl":  jsonl,
		"object": one,
		"array":  "[" + one + "]",
	} {
		b, err := Parse(strings.NewReader(in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !b.HasFinding("https://api.example.com/x", "Google API Key", "AIza-one") {
			t.Errorf("%s: finding not indexed under the registered domain", name)
		}
	}
	if _, err := Parse(strings.NewReader("not json")); err == nil {
		t.Error("garbage accepted")
	}
}

func TestKnownAndScriptChanges(t *testing.T) {
	b, err := Parse(strings.NewReader(jsonl))
	if err != nil {
		t.Fatal(err)
	}
	if b.Reports() != 2 {
		t.Errorf("reports = %d", b.Reports())
	}
	if !b.Known("https://www.example.com") || b.Known("https://nobody.example") {
		t.Error("Known is wrong")
	}
	if b.HasFinding("https://www.example.com", "JWT Token", "eyJ.x.y") {
		t.Error("a finding from another domain counted as seen")
	}
	ch := b.ScriptChanges("https://www.example.com", []ui.ScriptRecord{
		{Path: "https://www.example.com/a.js", SHA256: "bbb"},
		{Path: "https://www.example.com/new.js", SHA256: "nnn"},
	})
	if ch.Added != 1 || ch.Changed != 1 || ch.Removed != 1 {
		t.Errorf("changes %+v", ch)
	}
	_ = scanner.Finding{}
}
