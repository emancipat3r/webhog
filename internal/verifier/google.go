package verifier

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/emancipat3r/webhog/internal/scanner"
)

// googleProbe is one read-only call that tells whether a Google API key is
// enabled for an API. Each is the cheapest call the API offers; the
// geocoding and static map calls are billable to the key's owner at a
// fraction of a cent, which is also what makes an unrestricted key a
// finding.
type googleProbe struct {
	api string
	url string // with KEY where the key goes
}

var googleProbes = []googleProbe{
	{"generativelanguage", "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1&key=KEY"},
	{"geocoding", "https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway&key=KEY"},
	{"staticmap", "https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key=KEY"},
	{"youtube", "https://www.googleapis.com/youtube/v3/videos?part=id&id=dQw4w9WgXcQ&key=KEY"},
}

// verifyGoogleAPIKey probes each API in turn. An API answers 200 when the
// key is enabled for it, 403 when it is not enabled or the key is
// restricted to other referrers, and 400 with API_KEY_INVALID when the key
// does not exist. The Maps APIs answer 200 with a status field instead.
func verifyGoogleAPIKey(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	var enabled, denied []string
	invalid := false
	restricted := false
	for _, p := range googleProbes {
		code, body, _, err := v.do(ctx, request{url: strings.Replace(p.url, "KEY", f.Token, 1)})
		if err != nil {
			continue
		}
		text := string(body)
		switch {
		case code == http.StatusOK && !strings.Contains(text, "REQUEST_DENIED"):
			enabled = append(enabled, p.api)
		case strings.Contains(text, "API_KEY_INVALID") || strings.Contains(text, "API key not valid") || strings.Contains(text, "provided API key is invalid"):
			invalid = true
		case strings.Contains(text, "referer") || strings.Contains(text, "referrer") || strings.Contains(text, "API_KEY_HTTP_REFERRER_BLOCKED") || strings.Contains(text, "API_KEY_ANDROID_APP_BLOCKED") || strings.Contains(text, "API_KEY_IOS_APP_BLOCKED"):
			restricted = true
			denied = append(denied, p.api)
		default:
			denied = append(denied, p.api)
		}
	}
	sort.Strings(enabled)
	sort.Strings(denied)
	d := map[string]string{}
	if len(enabled) > 0 {
		d["apis_enabled"] = strings.Join(enabled, " ")
	}
	if len(denied) > 0 {
		d["apis_denied"] = strings.Join(denied, " ")
	}
	if restricted {
		d["restricted"] = "true"
	}
	switch {
	case len(enabled) > 0:
		return Result{Status: scanner.VerifyValid, Details: d}
	case invalid:
		return Result{Status: scanner.VerifyInvalid, Details: d}
	default:
		return Result{Status: scanner.VerifyUnknown, Details: d}
	}
}

// verifyFirebaseDatabase asks the realtime database for its root, shallow,
// which costs nothing and reads nothing but the top-level keys. 200 means
// the rules allow unauthenticated reads.
func verifyFirebaseDatabase(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	code, body, _, err := v.do(ctx, request{url: strings.TrimSuffix(f.Token, "/") + "/.json?shallow=true"})
	if err != nil {
		return unknown()
	}
	switch code {
	case http.StatusOK:
		var m map[string]any
		d := map[string]string{"open_read": "true"}
		if json.Unmarshal(body, &m) == nil {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if len(keys) > 10 {
				keys = keys[:10]
			}
			d["top_level_keys"] = strings.Join(keys, " ")
		}
		return Result{Status: scanner.VerifyValid, Details: d}
	case http.StatusUnauthorized, http.StatusForbidden:
		return Result{Status: scanner.VerifyInvalid, Details: map[string]string{"open_read": "false"}}
	}
	return unknown()
}

// verifyFirebaseConfig checks the services a Firebase config names for
// unauthenticated read access: Firestore documents, the storage bucket
// listing, and the realtime database. The config's api key is the token;
// the project id and bucket come from the finding's details, which the
// scanner fills from the config object.
func verifyFirebaseConfig(ctx context.Context, v *Verifier, f scanner.Finding) Result {
	d := map[string]string{}
	open := false
	locked := false
	if pid := f.Details["project_id"]; pid != "" {
		code, _, _, err := v.do(ctx, request{url: "https://firestore.googleapis.com/v1/projects/" + pid + "/databases/(default)/documents?pageSize=1&key=" + f.Token})
		if err == nil {
			switch {
			case code == http.StatusOK:
				d["firestore_open"] = "true"
				open = true
			case code == http.StatusForbidden || code == http.StatusUnauthorized:
				d["firestore_open"] = "false"
				locked = true
			}
		}
	}
	if bucket := f.Details["storage_bucket"]; bucket != "" {
		code, _, _, err := v.do(ctx, request{url: "https://firebasestorage.googleapis.com/v0/b/" + bucket + "/o?maxResults=1"})
		if err == nil {
			switch {
			case code == http.StatusOK:
				d["storage_listing_open"] = "true"
				open = true
			case code == http.StatusForbidden || code == http.StatusUnauthorized:
				d["storage_listing_open"] = "false"
				locked = true
			}
		}
	}
	if db := f.Details["database_url"]; db != "" {
		r := verifyFirebaseDatabase(ctx, v, scanner.Finding{Token: db})
		for k, val := range r.Details {
			d["rtdb_"+k] = val
		}
		if r.Status == scanner.VerifyValid {
			open = true
		} else if r.Status == scanner.VerifyInvalid {
			locked = true
		}
	}
	switch {
	case open:
		return Result{Status: scanner.VerifyValid, Details: d}
	case locked:
		return Result{Status: scanner.VerifyInvalid, Details: d}
	}
	return Result{Status: scanner.VerifyUnknown, Details: d}
}
