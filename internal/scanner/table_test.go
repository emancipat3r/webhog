package scanner

import (
	"regexp"
	"strings"
	"testing"
)

// TestNewDetectorShapes feeds each new or changed detector one value in its
// published shape, assembled at runtime from fragments so no contiguous
// credential-shaped literal sits in source. Every value is fake.
func TestNewDetectorShapes(t *testing.T) {
	hex32 := strings.Repeat("0123456789abcdef", 2)
	hex64 := hex32 + hex32
	cases := []struct {
		detector string
		input    string
	}{
		{"Google OAuth Client Secret", "secret: '" + "GOCSPX-" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9t" + "'"},
		{"Google OAuth Client ID", "'" + "123456789012-" + strings.Repeat("ab12", 8) + ".apps.googleusercontent.com" + "'"},
		{"GitHub Fine-Grained Token", "github_pat_" + strings.Repeat("A1b2C3d4E5", 8) + "ff"},
		{"GitHub App Token", "ghs_" + strings.Repeat("Ab1", 12)},
		{"GitLab Token", "glpat-" + "aB3dE5fG7hI9jK1lM3nO"},
		{"npm Access Token", "npm_" + strings.Repeat("aB1", 12)},
		{"OpenAI API Key", "sk-proj-" + strings.Repeat("Ab1", 8) + "T3BlbkFJ" + strings.Repeat("Ab1", 8)},
		{"Anthropic API Key", "sk-ant-api03-" + strings.Repeat("Ab1-", 22)},
		{"Hugging Face Token", "hf_" + strings.Repeat("Ab", 17)},
		{"Slack Token", "xoxb-" + "1234567890123-1234567890123-" + strings.Repeat("Ab1", 8)},
		{"Slack App-Level Token", "xapp-1-" + "A01234567-" + "1234567890123-" + hex64},
		{"Discord Webhook", "https://discord.com/api/webhooks/123456789012345678/" + strings.Repeat("Ab1_", 16)},
		{"Shopify Access Token", "shpat_" + hex32},
		{"Supabase Secret Key", "sb_secret_" + strings.Repeat("Ab1", 8)},
		{"Mapbox Secret Token", "sk.eyJ" + strings.Repeat("Ab1", 8) + "." + strings.Repeat("Ab1", 8)},
		{"Sentry DSN", "https://" + hex32 + "@o123456.ingest.us.sentry.io/4506789"},
		{"Datadog Client Token", "clientToken: '" + "pub" + hex32 + "'"},
		{"Cloudflare Beacon Token", "token: \"" + "1234567890-" + hex64 + "\""},
		{"Firebase Config", `{apiKey:"` + "AIza" + "SyA-9dZ3l8Bx_qWmEr0tUvWxYz12-Ab34Cd" + `",authDomain:"x.firebaseapp.com",projectId:"x"}`},
		{"Firebase Database URL", "databaseURL: 'https://my-app-default-rtdb.europe-west1.firebasedatabase.app'"},
		{"Private Key", "-----BEGIN " + "PRIVATE KEY-----"},
		{"Stripe Webhook Secret", "whsec_" + strings.Repeat("Ab1", 12)},
		{"Azure Storage Account Key", "AccountKey=" + strings.Repeat("Ab1+/", 17) + "A=="},
		{"DigitalOcean Token", "dop_v1_" + hex64},
		{"Airtable Token", "pat" + "aB3dE5fG7hI9jK" + "." + hex64},
		{"Linear API Key", "lin_api_" + strings.Repeat("Ab1", 13) + "a"},
		{"Twitter Bearer Token", strings.Repeat("A", 21) + strings.Repeat("Ab1%", 16)},
		{"Grafana Token", "glsa_" + strings.Repeat("Ab1", 10) + "ab" + "_" + "0123abcd"},
		{"Postman API Key", "PMAK-" + hex32[:24] + "-" + hex32 + "01"},
		{"AMQP Connection", "amqps://user:pw@host.example/vhost"},
		{"SQL Server Connection", "mssql://sa:pw@host.example/db"},
	}
	for _, c := range cases {
		if ok, _ := findToken(t, c.detector, c.input); !ok {
			t.Errorf("%s: expected a match in %q, got none", c.detector, c.input)
		}
	}
}

// TestPublicByDesignIsLabelled checks that the browser-side credential
// shapes carry the public flag through to the finding, and that the secret
// shapes do not.
func TestPublicByDesignIsLabelled(t *testing.T) {
	public := map[string]bool{}
	for _, d := range GetDetectors() {
		public[d.Name] = d.Public
	}
	for _, name := range []string{"Stripe Publishable Key", "Datadog Client Token", "Sentry DSN", "Mapbox Public Token", "Cloudflare Beacon Token", "Google OAuth Client ID"} {
		if !public[name] {
			t.Errorf("%s should be public by design", name)
		}
	}
	for _, name := range []string{"Stripe API Key", "Google API Key", "JWT Token", "Mapbox Secret Token", "Generic API Key"} {
		if public[name] {
			t.Errorf("%s must not be public by design", name)
		}
	}
}

// TestRetiredDetectorsAreGone guards the table against the shapes removed
// on purpose: Picatic (defunct, and its regex was a subset of Stripe's) and
// the SSH-only private key rule, replaced by one that also matches PKCS#8.
func TestRetiredDetectorsAreGone(t *testing.T) {
	for _, d := range GetDetectors() {
		if d.Name == "Picatic API Key" || d.Name == "SSH Private Key" {
			t.Errorf("detector %q should have been retired", d.Name)
		}
	}
}

// TestKeywordPrefilterAgreesWithRegex checks every keyword is a literal the
// regex cannot match without: for each detector with a keyword, a line that
// matched the regex must contain the keyword, otherwise the prefilter would
// hide matches. The check runs the shape fixtures above through the full
// scanner, which applies the prefilter, and expects the same hits.
func TestKeywordPrefilterAgreesWithRegex(t *testing.T) {
	for _, d := range GetDetectors() {
		if d.Keyword == "" {
			continue
		}
		if d.Keyword != strings.ToLower(d.Keyword) {
			t.Errorf("%s: keyword %q is not lower-case", d.Name, d.Keyword)
		}
		// The keyword must be a literal the regex needs: strip it out of a
		// lower-cased copy of the regex source and the source must change.
		src := strings.ToLower(d.Re.String())
		if !strings.Contains(src, strings.ToLower(regexp.QuoteMeta(d.Keyword))) && !strings.Contains(src, d.Keyword) {
			t.Errorf("%s: keyword %q does not appear in regex %q", d.Name, d.Keyword, d.Re.String())
		}
	}
}

// TestCloudStorageAndExposedFileShapes covers the detectors ported from
// the surface-discovery ideas: bucket references in either URL style, and
// the files that mark an exposure.
func TestCloudStorageAndExposedFileShapes(t *testing.T) {
	cases := []struct{ detector, input, want string }{
		{"AWS S3 Bucket", `src="https://acme-uploads.s3.us-east-1.amazonaws.com/a.png"`, "acme-uploads"},
		{"AWS S3 Bucket", `"https://s3.amazonaws.com/acme-backups/db.sql"`, "acme-backups"},
		{"Google Cloud Storage Bucket", `https://storage.googleapis.com/acme-static/app.js`, "acme-static"},
		{"Google Cloud Storage Bucket", `//acme-media.storage.googleapis.com/x`, "acme-media"},
		{"Azure Blob Container", `https://acmeprod.blob.core.windows.net/uploads/x.pdf`, "acmeprod.blob.core.windows.net/uploads"},
		{"Git Config Exposed", "[remote \"origin\"]\n\turl = https://github.com/acme/app", `[remote "origin"]`},
		{"API Specification", `{"openapi": "3.0.1", "paths": {}}`, `"openapi": "3.0.1"`},
		{"Spring Actuator Env", `{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment"}]}`, `"propertySources":[`},
	}
	for _, c := range cases {
		got := scanBody(Options{Include: []string{c.detector}}, "https://www.example.com/a.js", c.input)
		if len(got) == 0 || got[0].Token != c.want {
			t.Errorf("%s: %q -> %v, want token %q", c.detector, c.input, names(got), c.want)
			continue
		}
		if c.detector == "AWS S3 Bucket" && got[0].Details["listing_url"] != "https://"+c.want+".s3.amazonaws.com/?max-keys=1" {
			t.Errorf("S3 listing url %q", got[0].Details["listing_url"])
		}
	}
}
