package scanner

import "regexp"

// GetDetectors returns the detector table.
//
// Shapes come from each provider's published token format, the TruffleHog
// browser extension this tool started from, and the gitleaks and Kingfisher
// rule sets. A detector with a Keyword is only tried on lines containing that
// literal, which keeps large bundles cheap. A detector marked Public matches
// a credential the provider intends to ship to browsers; it is reported and
// labelled rather than dropped, because what a page serves is still a fact
// about the page.
//
// Detector names are part of the output contract: consumers match on them.
// Rename with care.
//
// # Generic detectors
//
// The four Generic rules anchor on a keyword (api_key, token/auth, secret,
// password) and capture the value that follows an assignment operator. They
// require the operator (: or =) between key and value. With whitespace
// alone allowed as the separator, the rules matched markup: a password
// input's attribute list, `password" placeholder=`, captured the attribute
// NAME as the token, and an HTML page yielded one such row per attribute.
// The value side is then filtered by genericLooksLikeACredential, so
// identifiers, placeholders and prose do not become rows.
func GetDetectors() []Detector {
	return []Detector{
		// ---- Cloud providers ----
		{
			Name: "AWS Access Key ID",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b`),
		},
		{
			Name:    "AWS Secret Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(?i)aws_?secret_?access_?key["']?[\s:=]*[:=][\s:=]*["']?([A-Za-z0-9/+=]{40})`),
			Keyword: "secret",
		},
		{
			Name:    "Amazon MWS Auth Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`),
			Keyword: "amzn.mws.",
		},
		{
			Name:    "AWS AppSync GraphQL Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(da2-[a-z0-9]{26})\b`),
			Keyword: "da2-",
		},
		{
			Name:    "Azure Storage Account Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(?i)accountkey=([A-Za-z0-9+/]{86}==)`),
			Keyword: "accountkey=",
		},
		{
			Name:    "DigitalOcean Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(do[opr]_v1_[a-f0-9]{64})\b`),
			Keyword: "_v1_",
		},
		{
			Name:    "HashiCorp Vault Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(hv[sb]\.[A-Za-z0-9_-]{24,})`),
			Keyword: "hv",
		},
		{
			Name:    "Pulumi Access Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(pul-[a-f0-9]{40})\b`),
			Keyword: "pul-",
		},
		{
			Name:    "Databricks Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(dapi[a-f0-9]{32})\b`),
			Keyword: "dapi",
		},
		{
			Name:    "PlanetScale Credential",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(pscale_(?:tkn|pw|oauth)_[A-Za-z0-9_.-]{32,})`),
			Keyword: "pscale_",
		},
		{
			Name:    "Doppler Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(dp\.(?:pt|st|ct|sa)\.[A-Za-z0-9]{40,})`),
			Keyword: "dp.",
		},

		// ---- Google ----
		{
			Name:    "Google API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`),
			Keyword: "aiza",
		},
		{
			Name:    "Google OAuth Client Secret",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(GOCSPX-[A-Za-z0-9_-]{28})\b`),
			Keyword: "gocspx-",
		},
		{
			Name:    "Google OAuth",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(?i)client_?secret["']?[\s:=]*[:=][\s:=]*["']?([0-9a-zA-Z_-]{24,})`),
			Keyword: "secret",
		},
		{
			Name:    "Google OAuth Client ID",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`\b([0-9]{10,13}-[a-z0-9]{32}\.apps\.googleusercontent\.com)\b`),
			Keyword: ".apps.googleusercontent.com",
			Public:  true,
		},
		{
			Name:    "Google OAuth Refresh Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(1//0[0-9A-Za-z_-]{40,})`),
			Keyword: "1//0",
		},
		{
			Name:    "Google Service Account",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`("type":\s*"service_account")`),
			Keyword: "service_account",
		},
		{
			Name:    "Firebase Config",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`(?i)apiKey["']?\s*[:=]\s*["'](AIza[0-9A-Za-z_-]{35})["'].{0,300}?(?:authDomain|projectId|databaseURL|storageBucket)`),
			Keyword: "apikey",
		},
		{
			Name:    "Firebase Database URL",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`(https://[a-z0-9-]+\.(?:firebaseio\.com|[a-z0-9-]+\.firebasedatabase\.app))`),
			Keyword: "firebase",
		},

		// ---- Facebook / Meta ----
		{
			Name:    "Facebook Access Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(EAA[A-Za-z0-9]{100,})`),
			Keyword: "eaa",
		},
		{
			Name:    "Facebook OAuth",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(?i)facebook.{0,20}['"]([0-9a-f]{32})['"]`),
			Keyword: "facebook",
		},

		// ---- Payments ----
		{
			Name:    "Stripe API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(sk_live_[0-9a-zA-Z]{24,})`),
			Keyword: "sk_live_",
		},
		{
			Name:    "Stripe Publishable Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(pk_live_[0-9a-zA-Z]{24,})`),
			Keyword: "pk_live_",
			Public:  true,
		},
		{
			Name:    "Stripe Restricted API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(rk_live_[0-9a-zA-Z]{24,})`),
			Keyword: "rk_live_",
		},
		{
			Name:    "Stripe Webhook Secret",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(whsec_[A-Za-z0-9]{32,})`),
			Keyword: "whsec_",
		},
		{
			Name:    "PayPal Braintree Access Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})`),
			Keyword: "access_token$production$",
		},
		{
			Name:    "Square Access Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(sq0atp-[0-9A-Za-z_-]{22})\b`),
			Keyword: "sq0atp-",
		},
		{
			Name:    "Square OAuth Secret",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(sq0csp-[0-9A-Za-z_-]{43})\b`),
			Keyword: "sq0csp-",
		},

		// ---- Source control and package registries ----
		{
			Name:    "GitHub Personal Access Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(ghp_[0-9a-zA-Z]{36})\b`),
			Keyword: "ghp_",
		},
		{
			Name:    "GitHub Fine-Grained Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(github_pat_[0-9A-Za-z_]{82})\b`),
			Keyword: "github_pat_",
		},
		{
			Name:    "GitHub OAuth Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(gho_[0-9a-zA-Z]{36})\b`),
			Keyword: "gho_",
		},
		{
			Name:    "GitHub App Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b((?:ghu|ghs|ghr)_[0-9a-zA-Z]{36,})\b`),
			Keyword: "gh",
		},
		{
			Name:    "GitHub Legacy Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(?i)github.{0,20}['"]([0-9a-f]{40})['"]`),
			Keyword: "github",
		},
		{
			Name:    "GitHub Auth Creds",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(https://[a-zA-Z0-9]{40}@github\.com)`),
			Keyword: "@github.com",
		},
		{
			Name:    "GitLab Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(gl(?:pat|rt|ptt|oas|dt|ft|soat|agent)-[0-9A-Za-z_-]{20,})`),
			Keyword: "gl",
		},
		{
			Name:    "npm Access Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`),
			Keyword: "npm_",
		},
		{
			Name:    "PyPI API Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})`),
			Keyword: "pypi-",
		},
		{
			Name:    "Atlassian API Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(ATATT3[A-Za-z0-9_=-]{150,})`),
			Keyword: "atatt3",
		},

		// ---- AI providers ----
		{
			Name:    "OpenAI API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(sk-(?:[A-Za-z0-9_-]+-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})`),
			Keyword: "t3blbkfj",
		},
		{
			Name:    "Anthropic API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})`),
			Keyword: "sk-ant-",
		},
		{
			Name:    "Hugging Face Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(hf_[A-Za-z0-9]{34})\b`),
			Keyword: "hf_",
		},
		{
			Name:    "Groq API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(gsk_[A-Za-z0-9]{52})\b`),
			Keyword: "gsk_",
		},
		{
			Name:    "Perplexity API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(pplx-[A-Za-z0-9]{48})\b`),
			Keyword: "pplx-",
		},
		{
			Name:    "Replicate API Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(r8_[A-Za-z0-9]{37})\b`),
			Keyword: "r8_",
		},

		// ---- Messaging and email ----
		{
			Name:    "Slack Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(xox[abeoprs]-[0-9]{8,13}-[0-9A-Za-z-]{20,})`),
			Keyword: "xox",
		},
		{
			Name:    "Slack App-Level Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(xapp-[0-9]-[A-Z0-9]{8,}-[0-9]{10,}-[a-f0-9]{32,})`),
			Keyword: "xapp-",
		},
		{
			Name:    "Slack Webhook",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)`),
			Keyword: "hooks.slack.com",
		},
		{
			Name: "Discord Bot Token",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`\b([MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b`),
		},
		{
			Name:    "Discord Webhook",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,})`),
			Keyword: "/api/webhooks/",
		},
		{
			Name:    "Telegram Bot API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b([0-9]{8,10}:AA[0-9A-Za-z_-]{33})\b`),
			Keyword: ":aa",
		},
		{
			Name: "Twilio API Key",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`\b(SK[0-9a-f]{32})\b`),
		},
		{
			Name:   "Twilio Account SID",
			Type:   DetectorConfig,
			Re:     regexp.MustCompile(`\b(AC[0-9a-f]{32})\b`),
			Public: true,
		},
		{
			Name:    "SendGrid API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b`),
			Keyword: "sg.",
		},
		{
			Name:    "MailGun API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(key-[0-9a-zA-Z]{32})\b`),
			Keyword: "key-",
		},
		{
			Name:    "MailChimp API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b([0-9a-f]{32}-us[0-9]{1,2})\b`),
			Keyword: "-us",
		},
		{
			Name:    "Postmark Server Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(?i)postmark.{0,30}['"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]`),
			Keyword: "postmark",
		},
		{
			Name:    "Resend API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(re_[A-Za-z0-9]{8}_[A-Za-z0-9]{24})\b`),
			Keyword: "re_",
		},
		{
			Name:    "Twitter Bearer Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{60,})`),
			Keyword: "aaaaaaaaaaaaaaaaaaaaa",
		},

		// ---- SaaS and infrastructure ----
		{
			Name:    "Heroku API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(?i)heroku.{0,20}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})`),
			Keyword: "heroku",
		},
		{
			Name:    "Shopify Access Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32})\b`),
			Keyword: "shp",
		},
		{
			Name: "Notion Integration Token",
			Type: DetectorSecret,
			Re:   regexp.MustCompile(`\b(ntn_[0-9A-Za-z]{40,}|secret_[0-9A-Za-z]{43})\b`),
		},
		{
			Name:    "Linear API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(lin_api_[0-9A-Za-z]{40})\b`),
			Keyword: "lin_api_",
		},
		{
			Name:    "Airtable Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(pat[0-9A-Za-z]{14}\.[0-9a-f]{64})\b`),
			Keyword: "pat",
		},
		{
			Name:    "Supabase Secret Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(sb_secret_[A-Za-z0-9_-]{20,})`),
			Keyword: "sb_secret_",
		},
		{
			Name:    "Supabase Publishable Key",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`\b(sb_publishable_[A-Za-z0-9_-]{20,})`),
			Keyword: "sb_publishable_",
			Public:  true,
		},
		{
			Name:    "Mapbox Secret Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(sk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})`),
			Keyword: "sk.eyj",
		},
		{
			Name:    "Mapbox Public Token",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`\b(pk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})`),
			Keyword: "pk.eyj",
			Public:  true,
		},
		{
			Name:    "Algolia API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(?i)algolia.{0,60}?['"]([0-9a-f]{32})['"]`),
			Keyword: "algolia",
		},
		{
			Name:    "Sentry DSN",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`(https://[0-9a-f]{32}@[a-z0-9.-]*sentry\.io/[0-9]+)`),
			Keyword: "sentry.io",
			Public:  true,
		},
		{
			Name:    "Datadog Client Token",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`\b(pub[0-9a-f]{32})\b`),
			Keyword: "pub",
			Public:  true,
		},
		{
			Name:   "Cloudflare Beacon Token",
			Type:   DetectorConfig,
			Re:     regexp.MustCompile(`\b([0-9]{10}-[0-9a-f]{64})\b`),
			Public: true,
		},
		{
			Name:    "Cloudflare API Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(?i)cloudflare.{0,40}?['"]([A-Za-z0-9_-]{40})['"]`),
			Keyword: "cloudflare",
		},
		{
			Name:    "New Relic User Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(NRAK-[A-Z0-9]{27})\b`),
			Keyword: "nrak-",
		},
		{
			Name:    "New Relic Browser Key",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`\b(NRJS-[a-f0-9]{19})\b`),
			Keyword: "nrjs-",
			Public:  true,
		},
		{
			Name:    "Grafana Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(glc_[A-Za-z0-9+/]{32,}={0,2}|glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})`),
			Keyword: "gl",
		},
		{
			Name:    "LaunchDarkly SDK Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(sdk-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
			Keyword: "sdk-",
		},
		{
			Name:    "Dropbox Access Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(sl\.[A-Za-z0-9_-]{130,})`),
			Keyword: "sl.",
		},
		{
			Name:    "Postman API Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b`),
			Keyword: "pmak-",
		},
		{
			Name:    "Contentful Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(CFPAT-[A-Za-z0-9_-]{43})\b`),
			Keyword: "cfpat-",
		},
		{
			Name:    "Age Secret Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`\b(AGE-SECRET-KEY-1[0-9A-Z]{58})\b`),
			Keyword: "age-secret-key-1",
		},

		// ---- Tokens and keys without a vendor ----
		{
			Name:    "JWT Token",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`),
			Keyword: "eyj",
		},
		{
			Name:    "Private Key",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`(-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----)`),
			Keyword: "private key",
		},
		{
			Name:    "Password in URL",
			Type:    DetectorSecret,
			Re:      regexp.MustCompile(`([a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["'\s])`),
			Keyword: "://",
		},

		// ---- Generic (keyword + assignment + value) ----
		{
			Name:    "Generic API Key",
			Type:    DetectorGeneric,
			Re:      regexp.MustCompile(`(?i)api[_-]?key["']?[\s:=]*[:=][\s:=]*["']?([A-Za-z0-9\-_]{20,})`),
			Keyword: "api",
		},
		{
			Name: "Generic Token",
			Type: DetectorGeneric,
			Re:   regexp.MustCompile(`(?i)(?:token|auth)["']?[\s:=]*[:=][\s:=]*["']?([A-Za-z0-9\-_\.]{20,})`),
		},
		{
			Name:    "Generic Secret",
			Type:    DetectorGeneric,
			Re:      regexp.MustCompile(`(?i)secret["']?[\s:=]*[:=][\s:=]*["']?([A-Za-z0-9\-_]{20,})`),
			Keyword: "secret",
		},
		{
			Name:    "Generic Password",
			Type:    DetectorGeneric,
			Re:      regexp.MustCompile(`(?i)password["']?[\s:=]*[:=][\s:=]*["']?([^"'\s]{8,})`),
			Keyword: "password",
		},

		// ---- Connection strings ----
		{
			Name:    "PostgreSQL Connection",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`(postgres(?:ql)?://[^\s'"]+)`),
			Keyword: "postgres",
		},
		{
			Name:    "MySQL Connection",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`(mysql://[^\s'"]+)`),
			Keyword: "mysql://",
		},
		{
			Name:    "MongoDB Connection",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`(mongodb(?:\+srv)?://[^\s'"]+)`),
			Keyword: "mongodb",
		},
		{
			Name:    "Redis Connection",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`(rediss?://[^\s'"]+)`),
			Keyword: "redis",
		},
		{
			Name:    "AMQP Connection",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`(amqps?://[^\s'"]+)`),
			Keyword: "amqp",
		},
		{
			Name:    "SQL Server Connection",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`((?:mssql|sqlserver)://[^\s'"]+)`),
			Keyword: "sql",
		},

		// ---- Cloud storage the app references ----
		{
			Name:    "AWS S3 Bucket",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`(?i)(?:https?:)?//([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|(?:https?:)?//s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])`),
			Keyword: "amazonaws.com",
		},
		{
			Name:    "Google Cloud Storage Bucket",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`(?i)(?:https?:)?//storage\.googleapis\.com/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])|(?:https?:)?//([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])\.storage\.googleapis\.com`),
			Keyword: "storage.googleapis.com",
		},
		{
			Name:    "Azure Blob Container",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`(?i)https?://([a-z0-9]{3,24}\.blob\.core\.windows\.net/[a-z0-9][a-z0-9-]{1,61}[a-z0-9])`),
			Keyword: ".blob.core.windows.net/",
		},

		// ---- Exposed files ----
		{
			Name:    "Git Config Exposed",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`(\[remote "[^"]+"\])`),
			Keyword: "[remote \"",
		},
		{
			Name:    "API Specification",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`("(?:openapi|swagger)"\s*:\s*"[0-9][0-9.]*")`),
			Keyword: "\"",
		},
		{
			Name:    "Spring Actuator Env",
			Type:    DetectorConfig,
			Re:      regexp.MustCompile(`("propertySources"\s*:\s*\[)`),
			Keyword: "propertysources",
		},

		// ---- Endpoints ----
		{
			Name: "Relative URL",
			Type: DetectorEndpoint,
			Re:   regexp.MustCompile(`["'](/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*)["']`),
		},
		{
			Name:    "HTTP URL",
			Type:    DetectorEndpoint,
			Re:      regexp.MustCompile(`(https?://[^\s"'<>]+)`),
			Keyword: "http",
		},
		{
			Name:    "WebSocket URL",
			Type:    DetectorEndpoint,
			Re:      regexp.MustCompile(`(wss?://[^\s"'<>]+)`),
			Keyword: "ws",
		},
		{
			Name:    "API Endpoint",
			Type:    DetectorEndpoint,
			Re:      regexp.MustCompile(`["'](/api/[^\s"']+)["']`),
			Keyword: "/api/",
		},
		{
			Name:    "GraphQL Endpoint",
			Type:    DetectorEndpoint,
			Re:      regexp.MustCompile(`(?i)["']([^"']*graphql[^"']*)["']`),
			Keyword: "graphql",
		},
		{
			Name: "Admin Endpoint",
			Type: DetectorEndpoint,
			Re:   regexp.MustCompile(`["'](/(?:admin|internal|private)/[^\s"']+)["']`),
		},
	}
}
