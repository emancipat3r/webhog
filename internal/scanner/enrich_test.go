package scanner

import (
	"encoding/base64"
	"testing"
	"time"
)

func b64u(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestJWTDetails(t *testing.T) {
	jwtNow = func() time.Time { return time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC) }
	defer func() { jwtNow = time.Now }()
	tok := b64u(`{"alg":"HS256","typ":"JWT","kid":"k1"}`) + "." +
		b64u(`{"iss":"https://abc.supabase.co/auth/v1","sub":"u1","role":"service_role","scope":"read write","iat":1792396800,"exp":1792400400,"aud":["a","b"]}`) + "." + "c2lnbmF0dXJlc2lnbmF0dXJl"
	d := jwtDetails(tok)
	want := map[string]string{
		"alg": "HS256", "kid": "k1", "iss": "https://abc.supabase.co/auth/v1", "sub": "u1",
		"role": "service_role", "supabase_role": "service_role", "scope": "read write", "aud": "a b",
		"iat": "2026-10-19T08:00:00Z", "exp": "2026-10-19T09:00:00Z", "expired": "true",
	}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("%s = %q, want %q", k, d[k], v)
		}
	}
	none := jwtDetails(b64u(`{"alg":"none"}`) + "." + b64u(`{"sub":"x"}`) + "." + "c2lnbmF0dXJlc2lnbmF0dXJl")
	if none["unsigned"] != "true" || none["expired"] != "no_exp" {
		t.Errorf("alg none: %v", none)
	}
	if jwtDetails("eyJnotreally.xx.yy") != nil {
		t.Error("undecodable token should give nil details")
	}
}

// TestAWSAccountFromKeyID uses the vector published with the technique
// (Tal Be'ery, 2024): ASIAY34FZKBOKMUTVV7A belongs to account 609629065308.
func TestAWSAccountFromKeyID(t *testing.T) {
	d := awsKeyDetails("ASIA" + "Y34FZKBOKMUTVV7A")
	if d["account_id"] != "609629065308" || d["key_type"] != "temporary" {
		t.Errorf("got %v", d)
	}
	if d := awsKeyDetails("AKIA" + "QYLPMN5HHHFPBSZ4"); d["key_type"] != "long_term" || d["account_id"] != "052310077262" {
		t.Errorf("got %v", d)
	}
}

func TestStripeAndSlackDetails(t *testing.T) {
	if d := stripeKeyDetails("rk_live_" + "x"); d["kind"] != "restricted" || d["mode"] != "live" {
		t.Errorf("stripe: %v", d)
	}
	if d := stripeKeyDetails("pk_test_" + "x"); d["kind"] != "publishable" || d["mode"] != "test" {
		t.Errorf("stripe: %v", d)
	}
	if d := slackTokenDetails("xoxb-" + "1"); d["kind"] != "bot" {
		t.Errorf("slack: %v", d)
	}
}

// TestEnrichmentRidesOnTheFinding checks the scanner attaches details and
// leaves them absent for tokens with nothing to derive.
func TestEnrichmentRidesOnTheFinding(t *testing.T) {
	got := scanBody(Options{}, "https://www.example.com/a.js", `key="ASIA`+`Y34FZKBOKMUTVV7A"`)
	if len(got) != 1 || got[0].Details["account_id"] != "609629065308" {
		t.Fatalf("got %+v", got)
	}
	got = scanBody(Options{}, "https://www.example.com/a.js", `k="AIzaSyA-9dZ3l8Bx_qWmEr0tUvWxYz12-Ab34Cd"`)
	if len(got) != 1 || got[0].Details != nil {
		t.Fatalf("got %+v", got)
	}
}

func TestFirebaseConfigDetailsComeFromTheLine(t *testing.T) {
	line := `const firebaseConfig={apiKey:"AIza` + `SyA-9dZ3l8Bx_qWmEr0tUvWxYz12-Ab34Cd",authDomain:"demo-app.firebaseapp.com",databaseURL:"https://demo-app-default-rtdb.firebaseio.com",projectId:"demo-app",storageBucket:"demo-app.appspot.com",messagingSenderId:"123",appId:"1:123:web:abc"};`
	got := scanBody(Options{Include: []string{"Firebase Config"}}, "https://www.example.com/a.js", line)
	if len(got) != 1 {
		t.Fatalf("got %d findings", len(got))
	}
	d := got[0].Details
	if d["project_id"] != "demo-app" || d["storage_bucket"] != "demo-app.appspot.com" || d["database_url"] != "https://demo-app-default-rtdb.firebaseio.com" || d["app_id"] != "1:123:web:abc" {
		t.Errorf("details %v", d)
	}
}
