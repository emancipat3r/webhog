// Package verifier attempts to validate discovered secrets against their
// providers' APIs so findings can be labeled active or inactive.
//
// All checks are READ-ONLY: they call identity/status endpoints (e.g. GitHub
// /user, Stripe /v1/balance, Slack auth.test) and never mutate provider state.
// Verification necessarily transmits the discovered credential to its provider;
// it is opt-in via the --verify flag and intended for authorized testing only.
package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/user/webhog/internal/scanner"
)

// checkFunc validates a single token and returns its verification status.
type checkFunc func(ctx context.Context, client *http.Client, token string) scanner.Verification

// Verifier dispatches findings to provider-specific checks.
type Verifier struct {
	client *http.Client
	checks map[string]checkFunc
}

// New creates a Verifier with a bounded per-request timeout.
func New(timeout time.Duration) *Verifier {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Verifier{
		client: &http.Client{Timeout: timeout},
		checks: map[string]checkFunc{
			"GitHub Personal Access Token": verifyGitHub,
			"GitHub OAuth Token":           verifyGitHub,
			"Stripe API Key":               verifyStripe,
			"Stripe Restricted API Key":    verifyStripe,
			"Slack Token":                  verifySlack,
			"SendGrid API Key":             verifySendGrid,
			"Telegram Bot API Key":         verifyTelegram,
			"MailGun API Key":              verifyMailgun,
		},
	}
}

// CanVerify reports whether a verifier exists for the given detector name.
func (v *Verifier) CanVerify(detector string) bool {
	_, ok := v.checks[detector]
	return ok
}

// Verify validates a token for the given detector. It returns VerifyNone when
// no verifier is registered for the detector.
func (v *Verifier) Verify(ctx context.Context, detector, token string) scanner.Verification {
	check, ok := v.checks[detector]
	if !ok {
		return scanner.VerifyNone
	}
	return check(ctx, v.client, token)
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

// do issues a request and returns the status code and body. A transport error
// yields code 0.
func do(ctx context.Context, client *http.Client, method, url string, headers map[string]string, basicUser, basicPass string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "webhog/0.1.0 (https://github.com/user/webhog)")
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	if basicUser != "" || basicPass != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func verifyGitHub(ctx context.Context, client *http.Client, token string) scanner.Verification {
	code, _, err := do(ctx, client, "GET", "https://api.github.com/user",
		map[string]string{"Authorization": "token " + token}, "", "")
	if err != nil {
		return scanner.VerifyUnknown
	}
	return statusFromCode(code)
}

func verifyStripe(ctx context.Context, client *http.Client, token string) scanner.Verification {
	// Restricted keys may lack balance read scope and return 403 while still
	// being valid credentials; treat 403 as authenticated.
	code, _, err := do(ctx, client, "GET", "https://api.stripe.com/v1/balance", nil, token, "")
	if err != nil {
		return scanner.VerifyUnknown
	}
	if code == http.StatusForbidden {
		return scanner.VerifyValid
	}
	return statusFromCode(code)
}

func verifySendGrid(ctx context.Context, client *http.Client, token string) scanner.Verification {
	code, _, err := do(ctx, client, "GET", "https://api.sendgrid.com/v3/scopes",
		map[string]string{"Authorization": "Bearer " + token}, "", "")
	if err != nil {
		return scanner.VerifyUnknown
	}
	return statusFromCode(code)
}

func verifyMailgun(ctx context.Context, client *http.Client, token string) scanner.Verification {
	code, _, err := do(ctx, client, "GET", "https://api.mailgun.net/v3/domains", nil, "api", token)
	if err != nil {
		return scanner.VerifyUnknown
	}
	return statusFromCode(code)
}

// okResponse models the {"ok": bool} envelope used by Slack and Telegram.
type okResponse struct {
	OK bool `json:"ok"`
}

func verifySlack(ctx context.Context, client *http.Client, token string) scanner.Verification {
	code, body, err := do(ctx, client, "POST", "https://slack.com/api/auth.test",
		map[string]string{"Authorization": "Bearer " + token}, "", "")
	if err != nil {
		return scanner.VerifyUnknown
	}
	// Slack returns HTTP 200 even for bad tokens; the verdict is in the body.
	if code == http.StatusOK {
		var r okResponse
		if json.Unmarshal(body, &r) == nil {
			if r.OK {
				return scanner.VerifyValid
			}
			return scanner.VerifyInvalid
		}
	}
	return statusFromCode(code)
}

func verifyTelegram(ctx context.Context, client *http.Client, token string) scanner.Verification {
	code, body, err := do(ctx, client, "GET",
		fmt.Sprintf("https://api.telegram.org/bot%s/getMe", token), nil, "", "")
	if err != nil {
		return scanner.VerifyUnknown
	}
	if code == http.StatusOK {
		var r okResponse
		if json.Unmarshal(body, &r) == nil {
			if r.OK {
				return scanner.VerifyValid
			}
			return scanner.VerifyInvalid
		}
	}
	return statusFromCode(code)
}
