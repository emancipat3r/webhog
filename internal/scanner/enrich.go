package scanner

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// firebaseField reads one quoted field of a Firebase config object.
var firebaseField = regexp.MustCompile(`(?i)(projectId|authDomain|databaseURL|storageBucket|appId|messagingSenderId)["']?\s*[:=]\s*["']([^"']+)["']`)

// firebaseConfigDetails pulls the identifiers out of the config object on
// the line, under snake_case keys. The verifier uses project_id,
// storage_bucket and database_url to test the project's rules.
func firebaseConfigDetails(line string) map[string]string {
	names := map[string]string{
		"projectid": "project_id", "authdomain": "auth_domain", "databaseurl": "database_url",
		"storagebucket": "storage_bucket", "appid": "app_id", "messagingsenderid": "messaging_sender_id",
	}
	d := map[string]string{}
	for _, m := range firebaseField.FindAllStringSubmatch(line, -1) {
		key := names[strings.ToLower(m[1])]
		if _, done := d[key]; !done {
			d[key] = m[2]
		}
	}
	return d
}

// enrich fills Finding.Details with facts derivable from the token and the
// line it sits on. It makes no network request. Each helper is a no-op for
// tokens it does not understand, so a detector table change never breaks
// enrichment.
func enrich(f *Finding, line string) {
	switch f.Detector {
	case "Firebase Config":
		f.Details = firebaseConfigDetails(line)
	case "AWS S3 Bucket":
		f.Details = map[string]string{"bucket": f.Token, "listing_url": "https://" + f.Token + ".s3.amazonaws.com/?max-keys=1"}
	case "Google Cloud Storage Bucket":
		f.Details = map[string]string{"bucket": f.Token, "listing_url": "https://storage.googleapis.com/storage/v1/b/" + f.Token + "/o?maxResults=1"}
	case "Azure Blob Container":
		f.Details = map[string]string{"container": f.Token, "listing_url": "https://" + f.Token + "?restype=container&comp=list&maxresults=1"}
	case "JWT Token":
		f.Details = jwtDetails(f.Token)
	case "AWS Access Key ID":
		f.Details = awsKeyDetails(f.Token)
	case "Stripe API Key", "Stripe Restricted API Key", "Stripe Publishable Key", "Stripe Webhook Secret":
		f.Details = stripeKeyDetails(f.Token)
	case "Slack Token":
		f.Details = slackTokenDetails(f.Token)
	}
	if len(f.Details) == 0 {
		f.Details = nil
	}
}

// b64urlJSON decodes one base64url segment of a JWT into a JSON object.
func b64urlJSON(seg string) map[string]any {
	seg = strings.TrimRight(seg, "=")
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// claimString renders a claim for Details: strings as they are, numbers
// without an exponent, lists joined by a space.
func claimString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			parts = append(parts, claimString(e))
		}
		return strings.Join(parts, " ")
	}
	return ""
}

// epochClaim reads a numeric-date claim as a time, or zero.
func epochClaim(v any) time.Time {
	n, ok := v.(float64)
	if !ok || n <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(n), 0).UTC()
}

// jwtNow is the clock used for the expired flag; tests override it.
var jwtNow = time.Now

// jwtDetails decodes a JWT's header and payload. It records the algorithm,
// the standard identity claims, issue and expiry as ISO-8601, whether the
// token is already expired, and the role or scope claims an authorization
// decision would hinge on. An unsigned token (alg none) is flagged.
func jwtDetails(token string) map[string]string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	header := b64urlJSON(parts[0])
	payload := b64urlJSON(parts[1])
	if header == nil && payload == nil {
		return nil
	}
	d := map[string]string{}
	if alg, ok := header["alg"].(string); ok && alg != "" {
		d["alg"] = alg
		if strings.EqualFold(alg, "none") {
			d["unsigned"] = "true"
		}
	}
	if kid := claimString(header["kid"]); kid != "" {
		d["kid"] = kid
	}
	for _, c := range []string{"iss", "sub", "aud", "azp", "email", "role", "roles", "scope", "scp", "permissions", "groups"} {
		if v := claimString(payload[c]); v != "" {
			d[c] = v
		}
	}
	if iat := epochClaim(payload["iat"]); !iat.IsZero() {
		d["iat"] = iat.Format(time.RFC3339)
	}
	if exp := epochClaim(payload["exp"]); !exp.IsZero() {
		d["exp"] = exp.Format(time.RFC3339)
		d["expired"] = strconv.FormatBool(exp.Before(jwtNow()))
	} else {
		d["expired"] = "no_exp"
	}
	if strings.Contains(claimString(payload["iss"]), "supabase") {
		if role := claimString(payload["role"]); role != "" {
			d["supabase_role"] = role
		}
	}
	return d
}

// awsKeyDetails decodes the AWS account ID embedded in an access key ID:
// the base32 body after the four-letter prefix carries the account number
// in its first 40 bits, offset by seven. The prefix says whether the key is
// long-lived (AKIA) or a temporary session credential (ASIA).
func awsKeyDetails(keyID string) map[string]string {
	if len(keyID) != 20 {
		return nil
	}
	d := map[string]string{}
	switch keyID[:4] {
	case "AKIA":
		d["key_type"] = "long_term"
	case "ASIA":
		d["key_type"] = "temporary"
	default:
		d["key_type"] = "other"
	}
	raw, err := base32.StdEncoding.DecodeString(keyID[4:])
	if err != nil || len(raw) < 6 {
		return d
	}
	var z uint64
	for _, b := range raw[:6] {
		z = z<<8 | uint64(b)
	}
	const mask = 0x7fffffffff80
	d["account_id"] = fmt.Sprintf("%012d", (z&mask)>>7)
	return d
}

// stripeKeyDetails reads the mode and kind off a Stripe key prefix.
func stripeKeyDetails(key string) map[string]string {
	d := map[string]string{}
	switch {
	case strings.HasPrefix(key, "sk_"):
		d["kind"] = "secret"
	case strings.HasPrefix(key, "rk_"):
		d["kind"] = "restricted"
	case strings.HasPrefix(key, "pk_"):
		d["kind"] = "publishable"
	case strings.HasPrefix(key, "whsec_"):
		d["kind"] = "webhook_signing"
		return d
	default:
		return nil
	}
	switch {
	case strings.Contains(key, "_live_"):
		d["mode"] = "live"
	case strings.Contains(key, "_test_"):
		d["mode"] = "test"
	}
	return d
}

// slackTokenDetails names the token family from its prefix.
func slackTokenDetails(token string) map[string]string {
	kinds := map[string]string{
		"xoxb": "bot", "xoxp": "user", "xoxa": "app", "xoxr": "refresh",
		"xoxs": "legacy_workspace", "xoxo": "legacy", "xapp": "app_level", "xoxe": "token_rotation",
	}
	if len(token) < 4 {
		return nil
	}
	if k, ok := kinds[token[:4]]; ok {
		return map[string]string{"kind": k}
	}
	return nil
}
