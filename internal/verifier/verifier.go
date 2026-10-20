// Package verifier attempts to validate discovered secrets against their
// providers' APIs so findings can be labeled active or inactive.
//
// All checks are READ-ONLY: they call identity, status or listing endpoints
// (GitHub /user, Stripe /v1/balance, Slack auth.test, STS GetCallerIdentity)
// and never mutate provider state. Verification necessarily transmits the
// discovered credential to its provider; it is opt-in via the --verify flag
// and intended for authorized testing only. Where a provider reports what a
// credential can do (OAuth scopes, an account identity, the APIs a key is
// enabled for) that is recorded on the finding's details.
package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/emancipat3r/webhog/internal/scanner"
	"github.com/emancipat3r/webhog/internal/version"
)

// Result is what a check learned: the status and any facts the provider
// returned about the credential.
type Result struct {
	Status  scanner.Verification
	Details map[string]string
}

func unknown() Result                      { return Result{Status: scanner.VerifyUnknown} }
func status(s scanner.Verification) Result { return Result{Status: s} }

// checkFunc validates one finding.
type checkFunc func(ctx context.Context, v *Verifier, f scanner.Finding) Result

// Verifier dispatches findings to provider-specific checks.
type Verifier struct {
	client *http.Client
	checks map[string]checkFunc
	// bases rewrites provider origins, so tests can point every check at a
	// local server. Keys and values are origins ("https://api.github.com").
	bases map[string]string
}

// New creates a Verifier with a bounded per-request timeout.
func New(timeout time.Duration) *Verifier {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	v := &Verifier{
		client: &http.Client{Timeout: timeout},
		bases:  map[string]string{},
	}
	v.checks = map[string]checkFunc{
		"GitHub Personal Access Token": verifyGitHub,
		"GitHub OAuth Token":           verifyGitHub,
		"GitHub Fine-Grained Token":    verifyGitHub,
		"GitHub App Token":             verifyGitHub,
		"GitLab Token":                 verifyGitLab,
		"npm Access Token":             verifyNPM,
		"Stripe API Key":               verifyStripe,
		"Stripe Restricted API Key":    verifyStripe,
		"Slack Token":                  verifySlack,
		"SendGrid API Key":             verifySendGrid,
		"Telegram Bot API Key":         verifyTelegram,
		"MailGun API Key":              verifyMailgun,
		"MailChimp API Key":            verifyMailchimp,
		"OpenAI API Key":               verifyOpenAI,
		"Anthropic API Key":            verifyAnthropic,
		"Hugging Face Token":           verifyHuggingFace,
		"Groq API Key":                 verifyGroq,
		"Replicate API Token":          verifyReplicate,
		"DigitalOcean Token":           verifyDigitalOcean,
		"Notion Integration Token":     verifyNotion,
		"Linear API Key":               verifyLinear,
		"Airtable Token":               verifyAirtable,
		"Discord Bot Token":            verifyDiscordBot,
		"Discord Webhook":              verifyDiscordWebhook,
		"Doppler Token":                verifyDoppler,
		"Dropbox Access Token":         verifyDropbox,
		"Postman API Key":              verifyPostman,
		"Mapbox Secret Token":          verifyMapbox,
		"Pulumi Access Token":          verifyPulumi,
		"New Relic User Key":           verifyNewRelic,
		"LaunchDarkly SDK Key":         verifyLaunchDarkly,
		"Contentful Token":             verifyContentful,
		"Resend API Key":               verifyResend,
		"Postmark Server Token":        verifyPostmark,
		"Cloudflare API Token":         verifyCloudflare,
		"Heroku API Key":               verifyHeroku,
		"Twitter Bearer Token":         verifyTwitter,
		"Square Access Token":          verifySquare,
		"Facebook Access Token":        verifyFacebook,
		"Google API Key":               verifyGoogleAPIKey,
		"Firebase Config":              verifyFirebaseConfig,
		"Firebase Database URL":        verifyFirebaseDatabase,
	}
	return v
}

// SetBase redirects requests for one provider origin to another; tests use
// it to stand a local server in for the provider.
func (v *Verifier) SetBase(origin, replacement string) {
	v.bases[origin] = replacement
}

// url rewrites a provider URL through SetBase.
func (v *Verifier) url(u string) string {
	for origin, repl := range v.bases {
		if strings.HasPrefix(u, origin) {
			return repl + strings.TrimPrefix(u, origin)
		}
	}
	return u
}

// CanVerify reports whether a verifier exists for the given detector name.
func (v *Verifier) CanVerify(detector string) bool {
	_, ok := v.checks[detector]
	return ok
}

// Verify validates a finding. It returns a VerifyNone status when no
// verifier is registered for the finding's detector.
func (v *Verifier) Verify(ctx context.Context, f scanner.Finding) Result {
	check, ok := v.checks[f.Detector]
	if !ok {
		return Result{Status: scanner.VerifyNone}
	}
	r := check(ctx, v, f)
	if len(r.Details) == 0 {
		r.Details = nil
	}
	return r
}

// statusFromCode maps a response code to a verification result using the common
// convention: 2xx means the credential authenticated, 401/403 means it was
// rejected, anything else is inconclusive.
func statusFromCode(code int) scanner.Verification {
	switch {
	case code >= 200 && code < 300:
		return scanner.VerifyValid
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return scanner.VerifyInvalid
	default:
		return scanner.VerifyUnknown
	}
}

// request describes one provider call.
type request struct {
	method  string
	url     string
	headers map[string]string
	user    string // basic auth
	pass    string
	body    string
}

// do issues a request and returns the status code, body and headers. A
// transport error yields code 0.
func (v *Verifier) do(ctx context.Context, r request) (int, []byte, http.Header, error) {
	method := r.method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if r.body != "" {
		body = strings.NewReader(r.body)
	}
	req, err := http.NewRequestWithContext(ctx, method, v.url(r.url), body)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", version.UserAgent())
	for k, val := range r.headers {
		req.Header.Set(k, val)
	}
	if r.user != "" || r.pass != "" {
		req.SetBasicAuth(r.user, r.pass)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, resp.Header, nil
}

// simple runs one request and maps the status code; pick extracts details
// from a successful body and may be nil.
func (v *Verifier) simple(ctx context.Context, r request, pick func(body []byte, hdr http.Header) map[string]string) Result {
	code, body, hdr, err := v.do(ctx, r)
	if err != nil {
		return unknown()
	}
	res := status(statusFromCode(code))
	if res.Status == scanner.VerifyValid && pick != nil {
		res.Details = pick(body, hdr)
	}
	return res
}

// bearer builds a GET with a Bearer token.
func bearer(url, token string) request {
	return request{url: url, headers: map[string]string{"Authorization": "Bearer " + token}}
}

// field returns a picker that copies the named top-level JSON string
// fields into details under the given names (pairs of json key, detail key).
func field(pairs ...string) func([]byte, http.Header) map[string]string {
	return func(body []byte, _ http.Header) map[string]string {
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			return nil
		}
		d := map[string]string{}
		for i := 0; i+1 < len(pairs); i += 2 {
			if s := jsonString(m[pairs[i]]); s != "" {
				d[pairs[i+1]] = s
			}
		}
		return d
	}
}

func jsonString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprintf("%.0f", x)
	case bool:
		return fmt.Sprint(x)
	case []any:
		var parts []string
		for _, e := range x {
			if s := jsonString(e); s != "" {
				parts = append(parts, s)
			}
		}
		sort.Strings(parts)
		return strings.Join(parts, " ")
	}
	return ""
}

// nested reads a dotted path out of a decoded JSON object.
func nested(m map[string]any, path string) string {
	cur := any(m)
	for _, k := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = obj[k]
	}
	return jsonString(cur)
}

// okResponse models the {"ok": bool} envelope used by Slack and Telegram.
type okResponse struct {
	OK bool `json:"ok"`
}

// ---- provider checks ----

func verifyGitHub(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	code, body, hdr, err := v.do(ctx, request{url: "https://api.github.com/user",
		headers: map[string]string{"Authorization": "token " + f.Token}})
	if err != nil {
		return unknown()
	}
	res := status(statusFromCode(code))
	if res.Status == scanner.VerifyValid {
		res.Details = field("login", "login")(body, hdr)
		if res.Details == nil {
			res.Details = map[string]string{}
		}
		if s := hdr.Get("X-OAuth-Scopes"); s != "" {
			res.Details["scopes"] = s
		}
	}
	return res
}

func verifyGitLab(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	if !strings.HasPrefix(f.Token, "glpat-") {
		return unknown()
	}
	return v.simple(ctx, request{url: "https://gitlab.com/api/v4/user",
		headers: map[string]string{"PRIVATE-TOKEN": f.Token}}, field("username", "username"))
}

func verifyNPM(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, bearer("https://registry.npmjs.org/-/whoami", f.Token), field("username", "username"))
}

func verifyStripe(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	// Restricted keys may lack balance read scope and return 403 while still
	// being valid credentials; treat 403 as authenticated.
	code, _, _, err := v.do(ctx, request{url: "https://api.stripe.com/v1/balance", user: f.Token})
	if err != nil {
		return unknown()
	}
	if code == http.StatusForbidden {
		return status(scanner.VerifyValid)
	}
	return status(statusFromCode(code))
}

func verifySendGrid(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, bearer("https://api.sendgrid.com/v3/scopes", f.Token), field("scopes", "scopes"))
}

func verifyMailgun(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{url: "https://api.mailgun.net/v3/domains", user: "api", pass: f.Token}, nil)
}

func verifyMailchimp(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	dc := f.Token[strings.LastIndex(f.Token, "-")+1:]
	return v.simple(ctx, request{url: "https://" + dc + ".api.mailchimp.com/3.0/ping", user: "anystring", pass: f.Token}, nil)
}

func verifySlack(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	code, body, _, err := v.do(ctx, request{method: http.MethodPost, url: "https://slack.com/api/auth.test",
		headers: map[string]string{"Authorization": "Bearer " + f.Token}})
	if err != nil {
		return unknown()
	}
	// Slack returns HTTP 200 even for bad tokens; the verdict is in the body.
	if code == http.StatusOK {
		var r okResponse
		if json.Unmarshal(body, &r) == nil {
			if r.OK {
				return Result{Status: scanner.VerifyValid, Details: field("team", "team", "user", "user", "url", "workspace")(body, nil)}
			}
			return status(scanner.VerifyInvalid)
		}
	}
	return status(statusFromCode(code))
}

func verifyTelegram(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	code, body, _, err := v.do(ctx, request{url: "https://api.telegram.org/bot" + f.Token + "/getMe"})
	if err != nil {
		return unknown()
	}
	if code == http.StatusOK {
		var r okResponse
		if json.Unmarshal(body, &r) == nil {
			if r.OK {
				var m map[string]any
				_ = json.Unmarshal(body, &m)
				return Result{Status: scanner.VerifyValid, Details: map[string]string{"username": nested(m, "result.username")}}
			}
			return status(scanner.VerifyInvalid)
		}
	}
	return status(statusFromCode(code))
}

func verifyOpenAI(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, bearer("https://api.openai.com/v1/models", f.Token), nil)
}

func verifyAnthropic(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{url: "https://api.anthropic.com/v1/models",
		headers: map[string]string{"x-api-key": f.Token, "anthropic-version": "2023-06-01"}}, nil)
}

func verifyHuggingFace(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, bearer("https://huggingface.co/api/whoami-v2", f.Token), func(body []byte, _ http.Header) map[string]string {
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			return nil
		}
		return map[string]string{"name": jsonString(m["name"]), "role": nested(m, "auth.accessToken.role")}
	})
}

func verifyGroq(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, bearer("https://api.groq.com/openai/v1/models", f.Token), nil)
}

func verifyReplicate(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{url: "https://api.replicate.com/v1/account",
		headers: map[string]string{"Authorization": "Token " + f.Token}}, field("username", "username"))
}

func verifyDigitalOcean(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, bearer("https://api.digitalocean.com/v2/account", f.Token), func(body []byte, _ http.Header) map[string]string {
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			return nil
		}
		return map[string]string{"email": nested(m, "account.email")}
	})
}

func verifyNotion(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{url: "https://api.notion.com/v1/users/me",
		headers: map[string]string{"Authorization": "Bearer " + f.Token, "Notion-Version": "2022-06-28"}}, field("name", "name", "type", "type"))
}

func verifyLinear(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{method: http.MethodPost, url: "https://api.linear.app/graphql",
		headers: map[string]string{"Authorization": f.Token, "Content-Type": "application/json"},
		body:    `{"query":"{ viewer { email } }"}`}, func(body []byte, _ http.Header) map[string]string {
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			return nil
		}
		if email := nested(m, "data.viewer.email"); email != "" {
			return map[string]string{"email": email}
		}
		return nil
	})
}

func verifyAirtable(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, bearer("https://api.airtable.com/v0/meta/whoami", f.Token), field("id", "user_id", "scopes", "scopes"))
}

func verifyDiscordBot(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{url: "https://discord.com/api/v10/users/@me",
		headers: map[string]string{"Authorization": "Bot " + f.Token}}, field("username", "username", "id", "user_id"))
}

// verifyDiscordWebhook GETs the webhook URL, which returns the webhook
// object without sending anything.
func verifyDiscordWebhook(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{url: f.Token}, field("name", "name", "channel_id", "channel_id", "guild_id", "guild_id"))
}

func verifyDoppler(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, bearer("https://api.doppler.com/v3/me", f.Token), nil)
}

func verifyDropbox(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{method: http.MethodPost, url: "https://api.dropboxapi.com/2/users/get_current_account",
		headers: map[string]string{"Authorization": "Bearer " + f.Token}}, field("email", "email"))
}

func verifyPostman(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{url: "https://api.getpostman.com/me", headers: map[string]string{"X-API-Key": f.Token}}, nil)
}

func verifyMapbox(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{url: "https://api.mapbox.com/tokens/v2?access_token=" + f.Token}, nil)
}

func verifyPulumi(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{url: "https://api.pulumi.com/api/user",
		headers: map[string]string{"Authorization": "token " + f.Token, "Accept": "application/vnd.pulumi+8"}}, field("githubLogin", "login"))
}

func verifyNewRelic(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{method: http.MethodPost, url: "https://api.newrelic.com/graphql",
		headers: map[string]string{"API-Key": f.Token, "Content-Type": "application/json"},
		body:    `{"query":"{ actor { user { email } } }"}`}, func(body []byte, _ http.Header) map[string]string {
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			return nil
		}
		return map[string]string{"email": nested(m, "data.actor.user.email")}
	})
}

func verifyLaunchDarkly(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{url: "https://sdk.launchdarkly.com/sdk/latest-all",
		headers: map[string]string{"Authorization": f.Token}}, func(body []byte, _ http.Header) map[string]string {
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			return nil
		}
		return map[string]string{"flags": fmt.Sprint(len(m))}
	})
}

func verifyContentful(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, bearer("https://api.contentful.com/spaces", f.Token), nil)
}

func verifyResend(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, bearer("https://api.resend.com/domains", f.Token), nil)
}

func verifyPostmark(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{url: "https://api.postmarkapp.com/server",
		headers: map[string]string{"X-Postmark-Server-Token": f.Token, "Accept": "application/json"}}, field("Name", "server"))
}

func verifyCloudflare(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, bearer("https://api.cloudflare.com/client/v4/user/tokens/verify", f.Token), func(body []byte, _ http.Header) map[string]string {
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			return nil
		}
		return map[string]string{"token_status": nested(m, "result.status")}
	})
}

func verifyHeroku(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{url: "https://api.heroku.com/account",
		headers: map[string]string{"Authorization": "Bearer " + f.Token, "Accept": "application/vnd.heroku+json; version=3"}}, field("email", "email"))
}

func verifyTwitter(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, bearer("https://api.twitter.com/2/tweets?ids=20", f.Token), nil)
}

func verifySquare(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	return v.simple(ctx, request{url: "https://connect.squareup.com/v2/locations",
		headers: map[string]string{"Authorization": "Bearer " + f.Token, "Square-Version": "2024-01-18"}}, nil)
}

func verifyFacebook(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	code, body, _, err := v.do(ctx, request{url: "https://graph.facebook.com/me?access_token=" + f.Token})
	if err != nil {
		return unknown()
	}
	if code == http.StatusBadRequest {
		return status(scanner.VerifyInvalid)
	}
	res := status(statusFromCode(code))
	if res.Status == scanner.VerifyValid {
		res.Details = field("name", "name", "id", "id")(body, nil)
	}
	return res
}
