package verifier

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emancipat3r/webhog/internal/scanner"
)

// TestSigV4MatchesTheAWSExample signs the request from the AWS Signature
// Version 4 documentation and checks the published signature.
func TestSigV4MatchesTheAWSExample(t *testing.T) {
	when := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	auth, hdrs, err := sigV4(http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", "",
		"AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "iam", when)
	if err != nil {
		t.Fatal(err)
	}
	const want = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if auth != want {
		t.Errorf("got  %s\nwant %s", auth, want)
	}
	if hdrs["X-Amz-Date"] != "20150830T123600Z" {
		t.Errorf("date header %q", hdrs["X-Amz-Date"])
	}
}

// provider stands in for one provider origin. Handlers see the real path.
func provider(t *testing.T, v *Verifier, origin string, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	v.SetBase(origin, srv.URL)
}

func TestGitHubScopesAndLogin(t *testing.T) {
	v := New(time.Second)
	provider(t, v, "https://api.github.com", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "token good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-OAuth-Scopes", "repo, read:org")
		_, _ = w.Write([]byte(`{"login":"octocat"}`))
	})
	r := v.Verify(t.Context(), scanner.Finding{Detector: "GitHub Personal Access Token", Token: "good"})
	if r.Status != scanner.VerifyValid || r.Details["scopes"] != "repo, read:org" || r.Details["login"] != "octocat" {
		t.Errorf("got %+v", r)
	}
	if r := v.Verify(t.Context(), scanner.Finding{Detector: "GitHub Fine-Grained Token", Token: "bad"}); r.Status != scanner.VerifyInvalid || r.Details != nil {
		t.Errorf("bad token: %+v", r)
	}
}

func TestSlackVerdictIsInTheBody(t *testing.T) {
	v := New(time.Second)
	provider(t, v, "https://slack.com", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/auth.test" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if strings.HasSuffix(r.Header.Get("Authorization"), "live") {
			_, _ = w.Write([]byte(`{"ok":true,"team":"Acme","user":"bot","url":"https://acme.slack.com/"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	})
	if r := v.Verify(t.Context(), scanner.Finding{Detector: "Slack Token", Token: "xoxb-live"}); r.Status != scanner.VerifyValid || r.Details["team"] != "Acme" || r.Details["workspace"] != "https://acme.slack.com/" {
		t.Errorf("live: %+v", r)
	}
	if r := v.Verify(t.Context(), scanner.Finding{Detector: "Slack Token", Token: "xoxb-dead"}); r.Status != scanner.VerifyInvalid {
		t.Errorf("dead: %+v", r)
	}
}

// TestGoogleKeyProbesReportEnabledAPIs: the key is enabled for Gemini and
// geocoding, not YouTube; a second key is restricted everywhere; a third
// does not exist.
func TestGoogleKeyProbesReportEnabledAPIs(t *testing.T) {
	v := New(time.Second)
	handler := func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		switch {
		case key == "nokey":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"status":"INVALID_ARGUMENT","details":[{"reason":"API_KEY_INVALID"}]}}`))
		case key == "locked":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"message":"Requests from referer <empty> are blocked.","status":"PERMISSION_DENIED"}}`))
		case strings.Contains(r.URL.Path, "geocode"):
			_, _ = w.Write([]byte(`{"status":"OK","results":[]}`))
		case strings.Contains(r.URL.Path, "staticmap"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`The Google Maps Platform server rejected your request. This API project is not authorized to use this API.`))
		case strings.Contains(r.URL.Path, "youtube"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"message":"YouTube Data API v3 has not been used in project"}}`))
		default:
			_, _ = w.Write([]byte(`{"models":[]}`))
		}
	}
	for _, origin := range []string{"https://generativelanguage.googleapis.com", "https://maps.googleapis.com", "https://www.googleapis.com"} {
		provider(t, v, origin, handler)
	}
	r := v.Verify(t.Context(), scanner.Finding{Detector: "Google API Key", Token: "open"})
	if r.Status != scanner.VerifyValid || r.Details["apis_enabled"] != "generativelanguage geocoding" || r.Details["apis_denied"] != "staticmap youtube" || r.Details["restricted"] != "" {
		t.Errorf("open key: %+v", r)
	}
	r = v.Verify(t.Context(), scanner.Finding{Detector: "Google API Key", Token: "locked"})
	if r.Status != scanner.VerifyUnknown || r.Details["restricted"] != "true" || r.Details["apis_enabled"] != "" {
		t.Errorf("locked key: %+v", r)
	}
	r = v.Verify(t.Context(), scanner.Finding{Detector: "Google API Key", Token: "nokey"})
	if r.Status != scanner.VerifyInvalid {
		t.Errorf("missing key: %+v", r)
	}
}

func TestFirebaseRulesAreProbedReadOnly(t *testing.T) {
	v := New(time.Second)
	var paths []string
	rtdb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.RequestURI())
		if strings.HasPrefix(r.URL.Path, "/open/") && r.URL.Query().Get("shallow") == "true" {
			_, _ = w.Write([]byte(`{"users":true,"orders":true}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Permission denied"}`))
	}))
	t.Cleanup(rtdb.Close)
	provider(t, v, "https://firestore.googleapis.com", func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusForbidden)
	})
	provider(t, v, "https://firebasestorage.googleapis.com", func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		_, _ = w.Write([]byte(`{"items":[]}`))
	})

	r := v.Verify(t.Context(), scanner.Finding{Detector: "Firebase Database URL", Token: rtdb.URL + "/open"})
	if r.Status != scanner.VerifyValid || r.Details["open_read"] != "true" || r.Details["top_level_keys"] != "orders users" {
		t.Errorf("open rtdb: %+v", r)
	}
	if r := v.Verify(t.Context(), scanner.Finding{Detector: "Firebase Database URL", Token: rtdb.URL}); r.Status != scanner.VerifyInvalid || r.Details["open_read"] != "false" {
		t.Errorf("locked rtdb: %+v", r)
	}
	r = v.Verify(t.Context(), scanner.Finding{Detector: "Firebase Config", Token: "AIzaKey",
		Details: map[string]string{"project_id": "proj-1", "storage_bucket": "proj-1.appspot.com"}})
	if r.Status != scanner.VerifyValid || r.Details["firestore_open"] != "false" || r.Details["storage_listing_open"] != "true" {
		t.Errorf("config: %+v", r)
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "GET ") {
			t.Errorf("non-GET request made: %s", p)
		}
	}
}

func TestAWSPairIsVerifiedThroughSTS(t *testing.T) {
	v := New(time.Second)
	provider(t, v, "https://sts.amazonaws.com", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIA") || r.Header.Get("X-Amz-Date") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if strings.Contains(auth, "Credential=AKIADEAD") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>`))
			return
		}
		_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/ci</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`))
	})
	r := v.VerifyAWSPair(t.Context(), "AKIA"+"LIVE1234567890AB", "secret")
	if r.Status != scanner.VerifyValid || r.Details["account_id"] != "123456789012" || !strings.HasSuffix(r.Details["arn"], "user/ci") {
		t.Errorf("live pair: %+v", r)
	}
	if r := v.VerifyAWSPair(t.Context(), "AKIADEAD", "secret"); r.Status != scanner.VerifyInvalid {
		t.Errorf("dead pair: %+v", r)
	}
}

// TestEveryRegisteredCheckIsReadOnly: no check issues a method other than
// GET or POST-to-an-identity-endpoint, and none reaches the real provider
// when every origin is redirected to a server that records the calls.
func TestEveryRegisteredCheckIsReadOnly(t *testing.T) {
	v := New(time.Second)
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.Host+r.URL.Path)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	for _, origin := range []string{
		"https://api.github.com", "https://gitlab.com", "https://registry.npmjs.org", "https://api.stripe.com", "https://slack.com",
		"https://api.sendgrid.com", "https://api.telegram.org", "https://api.mailgun.net", "https://us1.api.mailchimp.com",
		"https://api.openai.com", "https://api.anthropic.com", "https://huggingface.co", "https://api.groq.com", "https://api.replicate.com",
		"https://api.digitalocean.com", "https://api.notion.com", "https://api.linear.app", "https://api.airtable.com", "https://discord.com",
		"https://api.doppler.com", "https://api.dropboxapi.com", "https://api.getpostman.com", "https://api.mapbox.com", "https://api.pulumi.com",
		"https://api.newrelic.com", "https://sdk.launchdarkly.com", "https://api.contentful.com", "https://api.resend.com", "https://api.postmarkapp.com",
		"https://api.cloudflare.com", "https://api.heroku.com", "https://api.twitter.com", "https://connect.squareup.com", "https://graph.facebook.com",
		"https://generativelanguage.googleapis.com", "https://maps.googleapis.com", "https://www.googleapis.com", "https://firestore.googleapis.com", "https://firebasestorage.googleapis.com",
	} {
		v.SetBase(origin, srv.URL)
	}
	for name := range v.checks {
		f := scanner.Finding{Detector: name, Token: "glpat-x-us1", Details: map[string]string{"project_id": "p"}}
		if name == "Discord Webhook" || name == "Firebase Database URL" {
			f.Token = srv.URL + "/hook"
		}
		before := len(calls)
		r := v.Verify(t.Context(), f)
		if len(calls) == before {
			t.Errorf("%s made no request", name)
		}
		if r.Status == scanner.VerifyValid {
			t.Errorf("%s reported valid on a 401", name)
		}
	}
	for _, c := range calls {
		if !strings.HasPrefix(c, "GET ") && !strings.HasPrefix(c, "POST ") {
			t.Errorf("unexpected method in %s", c)
		}
		if strings.Contains(c, "127.0.0.1") == false && strings.Contains(c, "localhost") == false {
			t.Errorf("call escaped the test server: %s", c)
		}
	}
}
