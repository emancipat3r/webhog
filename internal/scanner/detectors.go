package scanner

import "regexp"

// GetDetectors returns all built-in detectors
// GetDetectors returns all built-in detectors
func GetDetectors() []Detector {
	return []Detector{
		// AWS Secrets
		{
			Name: "AWS Access Key ID",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})`),
		},
		{
			Name: "AWS Secret Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(?i)aws_?secret_?access_?key[\s:=]+["\']?([A-Za-z0-9/+=]{40})["\']?`),
		},
		{
			Name: "Amazon MWS Auth Token",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`),
		},
		{
			Name: "AWS AppSync GraphQL Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(da2-[a-z0-9]{26})`),
		},

		// Google
		{
			Name: "Google API Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(AIza[0-9A-Za-z\\-_]{35})`),
		},
		{
			Name: "Google OAuth",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(?i)client_?secret[\s:=]+["\']?([0-9a-zA-Z\-_]{24})["\']?`),
		},
		{
			Name: "Google Service Account",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`("type": "service_account")`),
		},

		// Facebook
		{
			Name: "Facebook Access Token",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(EAACEdEose0cBA[0-9A-Za-z]+)`),
		},
		{
			Name: "Facebook OAuth",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(?i)[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}['|"][0-9a-f]{32}['|"]`),
		},

		// Stripe
		{
			Name: "Stripe API Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(sk_live_[0-9a-zA-Z]{24,})`),
		},
		{
			Name: "Stripe Publishable Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(pk_live_[0-9a-zA-Z]{24,})`),
		},
		{
			Name: "Stripe Restricted API Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(rk_live_[0-9a-zA-Z]{24,})`),
		},

		// GitHub
		{
			Name: "GitHub Personal Access Token",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(ghp_[0-9a-zA-Z]{36})`),
		},
		{
			Name: "GitHub OAuth Token",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(gho_[0-9a-zA-Z]{36})`),
		},
		{
			Name: "GitHub Legacy Token",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(?i)[gG][iI][tT][hH][uU][bB].{0,20}['|"][0-9a-zA-Z]{35,40}['|"]`),
		},
		{
			Name: "GitHub Auth Creds",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(https://[a-zA-Z0-9]{40}@github\.com)`),
		},

		// Heroku
		{
			Name: "Heroku API Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(?i)[hH][eE][rR][oO][kK][uU].{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`),
		},

		// MailChimp
		{
			Name: "MailChimp API Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`([0-9a-f]{32}-us[0-9]{1,2})`),
		},

		// PayPal
		{
			Name: "PayPal Braintree Access Token",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})`),
		},

		// Picatic
		{
			Name: "Picatic API Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(sk_live_[0-9a-z]{32})`),
		},

		// Square
		{
			Name: "Square Access Token",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(sq0atp-[0-9A-Za-z\\-_]{22})`),
		},
		{
			Name: "Square OAuth Secret",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(sq0csp-[0-9A-Za-z\\-_]{43})`),
		},

		// Telegram
		{
			Name: "Telegram Bot API Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`([0-9]+:AA[0-9A-Za-z\\-_]{33})`),
		},

		// JWT
		{
			Name: "JWT Token",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`),
		},

		// Generic API Keys
		{
			Name: "Generic API Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(?i)api[_-]?key[\s:=]+["\']([A-Za-z0-9\-_]{20,})["\']`),
		},
		{
			Name: "Generic Token",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(?i)(?:token|auth)[\s:=]+["\']([A-Za-z0-9\-_\.]{20,})["\']`),
		},
		{
			Name: "Generic Secret",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(?i)secret[\s:=]+["\']([A-Za-z0-9\-_]{20,})["\']`),
		},
		{
			Name: "Generic Password",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(?i)password[\s:=]+["\']([^"'\s]{8,})["\']`),
		},
		{
			Name: "Password in URL",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`([a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["'\s])`),
		},

		// Database URLs
		{
			Name: "PostgreSQL Connection",
			Type: DetectorConfig,
			Re:   regexp.MustCompile(`(postgres(?:ql)?://[^\s'"]+)`),
		},
		{
			Name: "MySQL Connection",
			Type: DetectorConfig,
			Re:   regexp.MustCompile(`(mysql://[^\s'"]+)`),
		},
		{
			Name: "MongoDB Connection",
			Type: DetectorConfig,
			Re:   regexp.MustCompile(`(mongodb(?:\+srv)?://[^\s'"]+)`),
		},
		{
			Name: "Redis Connection",
			Type: DetectorConfig,
			Re:   regexp.MustCompile(`(redis://[^\s'"]+)`),
		},

		// Endpoints
		{
			Name: "Relative URL",
			Type: DetectorEndpoint,
			Re:   regexp.MustCompile(`["'](/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*)["']`),
		},
		{
			Name: "HTTP URL",
			Type: DetectorEndpoint,
			Re:   regexp.MustCompile(`(https?://[^\s"'<>]+)`),
		},
		{
			Name: "WebSocket URL",
			Type: DetectorEndpoint,
			Re:   regexp.MustCompile(`(wss?://[^\s"'<>]+)`),
		},
		{
			Name: "API Endpoint",
			Type: DetectorEndpoint,
			Re:   regexp.MustCompile(`["'](/api/[^\s"']+)["']`),
		},
		{
			Name: "GraphQL Endpoint",
			Type: DetectorEndpoint,
			Re:   regexp.MustCompile(`["']([^"']*graphql[^"']*)["']`),
		},
		{
			Name: "Admin Endpoint",
			Type: DetectorEndpoint,
			Re:   regexp.MustCompile(`["'](/(?:admin|internal|private)/[^\s"']+)["']`),
		},

		// Slack
		{
			Name: "Slack Webhook",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)`),
		},
		// Updated Slack Token to catch more variants
		{
			Name: "Slack Token",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`),
		},

		// Twilio
		{
			Name: "Twilio API Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(SK[0-9a-fA-F]{32})`),
		},

		// SendGrid
		{
			Name: "SendGrid API Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})`),
		},

		// MailGun
		{
			Name: "MailGun API Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(key-[0-9a-zA-Z]{32})`),
		},

		// SSH Private Key
		{
			Name: "SSH Private Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY(?: BLOCK)?-----)`),
		},
	}
}
