package scanner

import "regexp"

// GetDetectors returns all built-in detectors
func GetDetectors() []Detector {
	return []Detector{
		// AWS Secrets
		{
			Name: "AWS Access Key ID",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),
		},
		{
			Name: "AWS Secret Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`(?i)aws_?secret_?access_?key[\s:=]+["\']?([A-Za-z0-9/+=]{40})["\']?`),
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
			Re:   regexp.MustCompile(`(-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----)`),
		},
	}
}
