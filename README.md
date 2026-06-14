# Webhog

A headless web secret scanner CLI tool built in Go. Webhog scans web pages for exposed secrets, API keys, tokens, database credentials, and interesting endpoints.

Inspired by the [TruffleHog browser extension](https://github.com/trufflesecurity/Trufflehog-Chrome-Extension) and [gowitness](https://github.com/sensepost/gowitness)'s headless browser approach.

## Features

- **Dual Scanning Modes**
  - **Static Mode** (default): Fast HTTP-only scanning without JavaScript execution
  - **Headless Mode**: Full browser rendering for JavaScript-heavy SPAs using [go-rod](https://github.com/go-rod/rod)

- **Auto-Download Chromium**: When using headless mode, Chromium is automatically downloaded if not found (cached for future use)

- **Comprehensive Detection**
  - **TruffleHog Integration**: Includes 20+ secret detectors from the TruffleHog Browser Extension
  - AWS credentials (Access Keys, Secret Keys, AppSync, MWS)
  - Google API keys and OAuth tokens
  - Stripe API keys
  - GitHub Personal Access Tokens and Legacy Tokens
  - Facebook Access Tokens and OAuth
  - Heroku, MailChimp, PayPal, Picatic, Square, Telegram keys
  - JWT tokens
  - Password in URL
  - Database connection strings (PostgreSQL, MySQL, MongoDB, Redis)
  - SSH private keys
  - And more...

- **Advanced Attack Surface Mapping**
  - **HTML Scanning**: Scans the full HTML source, not just JavaScript blobs
  - **Endpoint Discovery**:
    - HTTP/HTTPS URLs
    - Relative URLs (e.g., `/api/v1/users`)
    - WebSocket URLs
    - API endpoints
    - GraphQL endpoints

- **Secret Verification** (opt-in via `--verify`)
  - Validates detected secrets against the provider's API and labels each one **active**, **inactive**, or **unverified**
  - All checks are read-only (identity/status endpoints — never mutates provider state)
  - Supported providers: GitHub (PAT & OAuth), Stripe (standard & restricted), Slack, SendGrid, Telegram bot, Mailgun

- **Technology Detection (Wappalyzer)**
  - Identifies CMS, frameworks, servers, and more using [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo)

- **Progressive Output**
  - **Streaming Results**: Findings are displayed immediately as they are found
  - **Smart Labels**: Context-aware labels (e.g., "URL" for endpoints, "Secret" for tokens)
  - **File Output**: Save clean, plain-text results to a file with `-o`/`--output`

- **Beautiful Output**
  - Styled terminal output using [Lip Gloss](https://github.com/charmbracelet/lipgloss)
  - JSON output for automation and CI/CD integration

## Installation

### From Source

```bash
git clone https://github.com/user/webhog
cd webhog
go build -o webhog ./cmd/webhog
```

### Requirements

- Go 1.25 or later
- (Optional) Chrome/Chromium browser for headless mode
  - If not installed, rod will auto-download Chromium on first use

## Usage

### Basic Scan (Static Mode)

```bash
webhog scan https://example.com
```

### Headless Mode (JavaScript Rendering)

```bash
webhog scan --headless https://example.com
```

### Scan Many Targets

Pass multiple URLs, read them from a file with `--list`, or pipe them on stdin
(one per line). Bare hostnames are upgraded to `https://`, so it slots straight
into a recon pipeline:

```bash
# from a subdomain enumeration tool
subfinder -d example.com | webhog scan --max-depth 1

# from a file
webhog scan --list hosts.txt --robots
```

Each target is scanned and crawled **independently** and gets its own report
(with `--same-domain` on, a target only crawls within its own apex domain — so a
50-host list is 50 scoped crawls). A failing host is reported and skipped rather
than aborting the run. With `--json`, one target emits a single object and many
targets emit an array.

### Crawl Multiple Pages

Follow links breadth-first up to a depth to expand the target's attack surface:

```bash
webhog scan --max-depth 2 https://example.com
```

Crawling expands the frontier two ways:

- **Navigation links** — `<a href>` anchors a user could click.
- **Discovered endpoints** — the URLs and API paths the scanner finds *inside
  JavaScript and HTML* (e.g. a `fetch("/api/v1/status")` or `"/internal/config.json"`
  buried in a bundle). These are fetched and scanned too, so secrets sitting
  behind JS-only paths are surfaced.

The crawl is scoped to the seed's **registered (apex) domain** by default, so
`api.example.com` and `www.example.com` are in scope but third-party hosts are
not. Pass `--same-domain=false` to follow off-domain links as well (noisier).
Redirect targets are de-duplicated (and redirect chains are bounded), and
`--max-pages` (default 200) caps the total crawl size.

Each finding is labeled with the page it came from, and the summary aggregates
pages crawled, JS blobs, and findings across the whole crawl.

### Enumerate from robots.txt

```bash
webhog scan --robots https://example.com
```

`--robots` treats `robots.txt` as an **enumeration source**, not a set of rules:
it fetches `robots.txt` and scans every `Disallow`/`Allow` path and `Sitemap:`
URL it lists. Disallowed paths are frequently the most interesting targets
(admin panels, internal tools, backups, staging), and they're scanned even at
`--max-depth 0`. Listed sitemaps are fetched too, and the URLs inside them are
picked up as endpoints and crawled when `--max-depth` allows.

> This intentionally ignores the crawl-restriction intent of `robots.txt`. It
> issues one extra request for the file itself and adds no load beyond the paths
> it discovers (still bounded by `--max-pages`). Use it only on authorized
> targets.

### Save Output to File

```bash
webhog scan https://example.com -o results.txt
```

### JSON Output

```bash
webhog scan --json https://example.com
```

### Verbose Mode

```bash
webhog scan -v https://example.com
```

### Verify Detected Secrets

Validate each detected secret against its provider's API and label it active/inactive:

```bash
webhog scan --verify https://example.com
```

> `--verify` sends the discovered credentials to their providers over read-only
> endpoints (e.g. GitHub `/user`, Stripe `/v1/balance`, Slack `auth.test`). Only
> run it against targets you are authorized to test.

## Examples

### Scan a Single Page

```bash
$ webhog scan https://example.com
...
Webhog Scan Results

╭────────────────────────────────────────╮
│                                        │
│  URL: https://example.com              │
│  Tech: WordPress, Nginx                │
│  JS Blobs: 5                           │
│  Total Findings: 12                    │
│                                        │
│  By Type:                              │
│    Secrets:       3                    │
│    Configuration: 1                    │
│    Endpoints:     8                    │
│    Generic:       0                    │
│                                        │
╰────────────────────────────────────────╯
```

### Headless Mode for SPAs

```bash
webhog scan --headless --timeout 60s https://app.example.com
```

### Output as JSON for CI/CD

```bash
webhog scan --json https://example.com | jq '.findings[] | select(.type=="secret")'
```

## Command-Line Options

### Global Flags

- `-v, --verbose`: Verbose output
- `--no-color`: Disable colored output
- `--config`: Path to config file

### Scan Command Flags

**Mode:**
- `--headless`: Use headless browser rendering (default: false)
- `--timeout`: Page load timeout (default: 30s)

**Input:**
- `-l, --list`: Read targets (one per line) from a file. Targets may also be passed as arguments or piped on stdin; bare hostnames default to `https://`.

**Output:**
- `-o, --output`: Write results to file
- `--json`: Output results as JSON
- `--quiet`: Minimal output
- `--plain`: Disable styled output

**Crawling:**
- `--max-depth`: Maximum crawl depth (default: 0 = single URL only). At each page, both `<a href>` anchors and endpoints discovered in JS/HTML are followed breadth-first.
- `--max-pages`: Maximum number of pages to crawl (default: 200; 0 = unlimited)
- `--same-domain`: Restrict the crawl to the seed's registered (apex) domain (default: true; e.g. `api.example.com` and `www.example.com` both count for a seed on `example.com`). Set `--same-domain=false` to follow off-domain links too.
- `--robots`: Use `robots.txt` as an enumeration source — scan its `Disallow`/`Allow` paths and `Sitemap:` URLs (default: false). Does **not** honor crawl restrictions; authorized targets only.

**Detection:**
- `--verify`: Validate detected secrets against provider APIs (read-only). Makes outbound requests using the discovered credentials — only use against targets you're authorized to test.
- `--include-entropy`: Enable entropy-based detection
- `--min-entropy`: Minimum entropy threshold (default: 4.5)
- `--min-length`: Minimum token length for detection (default: 20)

## Detection Rules

Webhog includes built-in detectors for:

### Secrets & Keys
- AWS Access Key IDs and Secret Keys, MWS, AppSync
- Google API Keys and OAuth tokens
- Stripe API keys (live and test)
- GitHub Personal Access Tokens
- Facebook Access Tokens
- Heroku, MailChimp, PayPal, Picatic, Square, Telegram
- JWT tokens
- Generic API keys, tokens, secrets, passwords
- SSH private keys

### Configuration
- Database connection strings (PostgreSQL, MySQL, MongoDB, Redis)
- Passwords in URLs

### Endpoints
- HTTP/HTTPS URLs and Relative Paths
- WebSocket URLs
- API endpoints (`/api/*`)
- GraphQL endpoints

## Architecture

```
webhog/
├── cmd/webhog/          # CLI entry point (Cobra)
│   ├── main.go
│   ├── root.go
│   └── scan.go
├── internal/
│   ├── renderer/        # Page rendering (static & headless)
│   ├── crawler/         # Breadth-first multi-page crawling
│   ├── scanner/         # Secret detection (Regex & Entropy)
│   ├── verifier/        # Live credential validation (--verify)
│   ├── tech/            # Wappalyzer integration
│   ├── ui/              # Styled output (Lip Gloss)
│   └── config/          # Configuration
└── go.mod
```

## Comparison to Other Tools

### vs TruffleHog Browser Extension
- **Webhog**: CLI tool, automation-friendly, works offline, no manual browsing
- **Extension**: Passive scanning while browsing, requires browser

### vs Traditional Secret Scanners (TruffleHog CLI, GitLeaks)
- **Webhog**: Scans live web applications, handles JavaScript rendering
- **Traditional**: Scans git repositories and source code

### vs gowitness
- **Webhog**: Focuses on secret detection, not screenshots
- **gowitness**: Screenshot tool with some metadata collection

## Use Cases

- **Bug Bounty Hunting**: Find exposed credentials on web applications
- **Penetration Testing**: Discover secrets and sensitive endpoints
- **Security Audits**: Scan your own applications for exposed secrets
- **CI/CD Integration**: Automated security scanning in pipelines
- **Red Team Operations**: Reconnaissance and credential discovery

## Limitations

- Crawling follows `<a href>` anchors and endpoints found via the scanner's regexes in JS/HTML, but not URLs assembled dynamically at runtime (e.g. string-concatenated paths); it crawls pages sequentially
- Static mode doesn't execute JavaScript (use `--headless` for SPAs)
- Headless mode requires more resources and time

## Contributing

Contributions are welcome! Areas for improvement:
- Additional secret detectors and verifiers
- Concurrent (parallel) crawling
- Custom detector rules
- Performance optimizations
- Network request interception in headless mode

## License

See [LICENSE](LICENSE) file.

## Credits

Built with:
- [Cobra](https://github.com/spf13/cobra) - CLI framework
- [go-rod](https://github.com/go-rod/rod) - Headless browser automation
- [Lip Gloss](https://github.com/charmbracelet/lipgloss) - Terminal styling
- [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) - Technology detection

Inspired by:
- [TruffleHog Chrome Extension](https://github.com/trufflesecurity/Trufflehog-Chrome-Extension)
- [gowitness](https://github.com/sensepost/gowitness)
