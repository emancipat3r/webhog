package verifier

import (
	"net/http"
	"testing"
	"time"

	"github.com/user/webhog/internal/scanner"
)

func TestStatusFromCode(t *testing.T) {
	cases := []struct {
		code int
		want scanner.Verification
	}{
		{http.StatusOK, scanner.VerifyValid},
		{http.StatusNoContent, scanner.VerifyValid},
		{http.StatusUnauthorized, scanner.VerifyInvalid},
		{http.StatusForbidden, scanner.VerifyInvalid},
		{http.StatusInternalServerError, scanner.VerifyUnknown},
		{http.StatusTooManyRequests, scanner.VerifyUnknown},
	}
	for _, c := range cases {
		if got := statusFromCode(c.code); got != c.want {
			t.Errorf("statusFromCode(%d) = %q, want %q", c.code, got, c.want)
		}
	}
}

func TestCanVerify(t *testing.T) {
	v := New(time.Second)
	if !v.CanVerify("GitHub Personal Access Token") {
		t.Error("expected a verifier for GitHub Personal Access Token")
	}
	if v.CanVerify("Google API Key") {
		t.Error("did not expect a verifier for Google API Key")
	}
}

// TestVerifyUnregisteredDetector ensures detectors without a verifier report
// VerifyNone rather than blocking on a network call.
func TestVerifyUnregisteredDetector(t *testing.T) {
	v := New(time.Second)
	if got := v.Verify(t.Context(), "Google API Key", "AIzaWhatever"); got != scanner.VerifyNone {
		t.Errorf("Verify for unregistered detector = %q, want %q", got, scanner.VerifyNone)
	}
}
