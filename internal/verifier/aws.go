package verifier

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/emancipat3r/webhog/internal/scanner"
)

// sigV4 signs a request the way AWS Signature Version 4 requires. It covers
// what STS needs: a host header, the date header, and a payload hash. It
// returns the Authorization header value.
func sigV4(method, rawURL, body, accessKey, secretKey, region, service string, now time.Time) (string, map[string]string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", nil, err
	}
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := amzDate[:8]

	headers := map[string]string{
		"host":         u.Host,
		"x-amz-date":   amzDate,
		"content-type": "application/x-www-form-urlencoded; charset=utf-8",
	}
	var names []string
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + strings.TrimSpace(headers[k]) + "\n")
	}
	signed := strings.Join(names, ";")

	// Query parameters sorted by name, each value encoded.
	q := u.Query()
	var qnames []string
	for k := range q {
		qnames = append(qnames, k)
	}
	sort.Strings(qnames)
	var canonQuery []string
	for _, k := range qnames {
		vals := q[k]
		sort.Strings(vals)
		for _, val := range vals {
			canonQuery = append(canonQuery, awsEscape(k)+"="+awsEscape(val))
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	payloadHash := sha256hex([]byte(body))
	canonical := strings.Join([]string{method, path, strings.Join(canonQuery, "&"), canonHeaders.String(), signed, payloadHash}, "\n")

	scope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, sha256hex([]byte(canonical))}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, toSign))

	auth := "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + signature
	out := map[string]string{"X-Amz-Date": amzDate, "Content-Type": headers["content-type"]}
	return auth, out, nil
}

func awsEscape(s string) string {
	// RFC 3986 with every byte outside unreserved escaped, which is what
	// url.QueryEscape does except for spaces and the tilde.
	return strings.ReplaceAll(strings.ReplaceAll(url.QueryEscape(s), "+", "%20"), "%7E", "~")
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// callerIdentity is the part of the STS response webhog reads.
type callerIdentity struct {
	Account string `xml:"GetCallerIdentityResult>Account"`
	Arn     string `xml:"GetCallerIdentityResult>Arn"`
	UserID  string `xml:"GetCallerIdentityResult>UserId"`
}

// VerifyAWSPair calls STS GetCallerIdentity with an access key and secret
// found together. The call needs no permissions and changes nothing; it
// answers with the account and the principal the pair belongs to.
func (v *Verifier) VerifyAWSPair(ctx context.Context, accessKey, secretKey string) Result {
	const endpoint = "https://sts.amazonaws.com/"
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	auth, hdrs, err := sigV4(http.MethodPost, endpoint, body, accessKey, secretKey, "us-east-1", "sts", time.Now())
	if err != nil {
		return unknown()
	}
	hdrs["Authorization"] = auth
	code, resp, _, err := v.do(ctx, request{method: http.MethodPost, url: endpoint, headers: hdrs, body: body})
	if err != nil {
		return unknown()
	}
	if code == http.StatusForbidden || code == http.StatusUnauthorized {
		return status(scanner.VerifyInvalid)
	}
	if code != http.StatusOK {
		return unknown()
	}
	var id callerIdentity
	if xml.Unmarshal(resp, &id) != nil {
		return unknown()
	}
	return Result{Status: scanner.VerifyValid, Details: map[string]string{"account_id": id.Account, "arn": id.Arn, "user_id": id.UserID}}
}
