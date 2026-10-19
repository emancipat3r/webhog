package scanner

import "testing"

// findToken runs a single named detector against input and returns the first
// captured token, if any.
func findToken(t *testing.T, name, input string) (bool, string) {
	t.Helper()
	for _, d := range GetDetectors() {
		if d.Name != name {
			continue
		}
		m := d.Re.FindStringSubmatch(input)
		if len(m) >= 2 {
			return true, m[1]
		}
		return false, ""
	}
	t.Fatalf("detector %q not found", name)
	return false, ""
}

// TestHyphenatedKeysMatch guards the character-class fix: these detectors
// previously used `\\-_`, which RE2 parsed as the range \x5C-\x5F and so failed
// to match hyphens that legitimately appear in these credentials.
func TestHyphenatedKeysMatch(t *testing.T) {
	// Fixture tokens are assembled from fragments so they exercise the detectors
	// at runtime without embedding a contiguous secret literal that would trip
	// source secret-scanners (e.g. GitHub push protection). All values are fake.
	cases := []struct {
		detector string
		input    string
	}{
		{"Google API Key", "var k = '" + "AIza" + "SyA-9dZ3l8Bx_qWmEr0tUvWxYz12-Ab34Cd';"},
		{"Square Access Token", "sq0atp-" + "0123456789AB-cdef_GHIJ"},
		{"Telegram Bot API Key", "110201543:" + "AA" + "HdqTcv-CH1vGW-Z_mK-uY_xY_qWmEr0tU"},
	}
	for _, c := range cases {
		if ok, _ := findToken(t, c.detector, c.input); !ok {
			t.Errorf("%s: expected a match in %q, got none", c.detector, c.input)
		}
	}
}

// TestJSONStyleGenericKey guards that the generic detectors match JSON-style
// config (`"api_key":"..."`), not just env-style assignments.
func TestJSONStyleGenericKey(t *testing.T) {
	if ok, _ := findToken(t, "Generic API Key", `{"api_key":"abcdef0123456789ABCDEF"}`); !ok {
		t.Error("Generic API Key: expected JSON-style match")
	}
}

// TestGenericDetectorsNeedAnAssignmentOperator guards the separator fix. A
// password input's attributes used to be captured as values: `password`
// followed by whitespace and `placeholder=` matched Generic Password with the
// attribute NAME as the token. A key/value pair carries : or =; whitespace on
// its own is markup or prose. Env, JSON and JS assignment styles still match.
func TestGenericDetectorsNeedAnAssignmentOperator(t *testing.T) {
	markup := `<input type="password" placeholder="Enter your password" required="" autocomplete="current-password" ng-model="vm.password">`
	if ok, tok := findToken(t, "Generic Password", markup); ok {
		t.Errorf("Generic Password: matched %q inside markup with no assignment operator", tok)
	}
	if ok, tok := findToken(t, "Generic Token", `<meta name="csrf-token" content="x"> token spoken here`); ok {
		t.Errorf("Generic Token: matched %q with whitespace alone as the separator", tok)
	}
	still := []struct{ detector, input, want string }{
		{"Generic Password", `password = "hunter2hunter2"`, "hunter2hunter2"},
		{"Generic Password", `{"password":"hunter2hunter2"}`, "hunter2hunter2"},
		{"Generic Password", `PASSWORD=hunter2hunter2`, "hunter2hunter2"},
		{"Generic API Key", `{"api_key":"abcdef0123456789ABCDEF"}`, "abcdef0123456789ABCDEF"},
		{"Generic API Key", `api-key: abcdef0123456789ABCDEF`, "abcdef0123456789ABCDEF"},
		{"Generic Token", `clientToken: 'abcdef0123456789ABCDEF'`, "abcdef0123456789ABCDEF"},
		{"Generic Secret", `secret === "abcdef0123456789ABCDEF"`, "abcdef0123456789ABCDEF"},
	}
	for _, c := range still {
		ok, tok := findToken(t, c.detector, c.input)
		if !ok || tok != c.want {
			t.Errorf("%s: %q -> (%v, %q), want %q", c.detector, c.input, ok, tok, c.want)
		}
	}
}
