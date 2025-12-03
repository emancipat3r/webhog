# Webhog

A headless web secret scanner CLI tool built in Go. Webhog scans web pages for exposed secrets, API keys, tokens, database credentials, and interesting endpoints.

Inspired by the [TruffleHog browser extension](https://github.com/trufflesecurity/Trufflehog-Chrome-Extension) and [gowitness](https://github.com/sensepost/gowitness)'s headless browser approach.

## Features

- **Dual Scanning Modes**
  - **Static Mode** (default): Fast HTTP-only scanning without JavaScript execution
  - **Headless Mode**: Full browser rendering for JavaScript-heavy SPAs using [go-rod](https://github.com/go-rod/rod)

- **Auto-Download Chromium**: When using headless mode, Chromium is automatically downloaded if not found (cached for future use)

- **Comprehensive Detection**
  - AWS credentials (Access Keys, Secret Keys)
  - Google API keys and OAuth tokens
  - Stripe API keys
  - GitHub Personal Access Tokens
  - JWT tokens
  - Generic API keys, tokens, secrets, passwords
  - Database connection strings (PostgreSQL, MySQL, MongoDB, Redis)
  - Slack webhooks and tokens
  - SSH private keys
  - And more...

- **Endpoint Discovery**
  - HTTP/HTTPS URLs
  - WebSocket URLs
  - API endpoints
  - GraphQL endpoints
  - Admin/internal routes

- **Beautiful Output**
  - Styled terminal output using [Lip Gloss](https://github.com/charmbracelet/lipgloss)
  - JSON output for automation and CI/CD integration
  - Plain text mode for piping

## Installation

### From Source

```bash
git clone https://github.com/user/webhog
cd webhog
go build -o webhog ./cmd/webhog
```

### Requirements

- Go 1.22 or later
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

### JSON Output

```bash
webhog scan --json https://example.com
```

### Verbose Mode

```bash
webhog scan -v https://example.com
```

## Examples

### Scan a Single Page

```bash
$ webhog scan https://example.com

Webhog Scan Results

╭────────────────────────────────────────╮
│                                        │
│  URL: https://example.com              │
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

**Crawling (Future):**
- `--max-depth`: Maximum crawl depth (default: 0 = single URL only)
- `--same-domain`: Only follow links on same domain

**Output:**
- `--json`: Output results as JSON
- `--quiet`: Minimal output
- `--plain`: Disable styled output

**Detection:**
- `--include-entropy`: Enable entropy-based detection
- `--min-entropy`: Minimum entropy threshold (default: 4.5)
- `--min-length`: Minimum token length for detection (default: 20)

## Detection Rules

Webhog includes built-in detectors for:

### Secrets & Keys
- AWS Access Key IDs and Secret Keys
- Google API Keys and OAuth tokens
- Stripe API keys (live and test)
- GitHub Personal Access Tokens
- JWT tokens
- Slack webhooks and tokens
- Twilio API keys
- SendGrid API keys
- MailGun API keys
- SSH private keys
- Generic API keys, tokens, secrets, passwords

### Configuration
- PostgreSQL connection strings
- MySQL connection strings
- MongoDB connection strings
- Redis connection strings

### Endpoints
- HTTP/HTTPS URLs
- WebSocket URLs
- API endpoints (`/api/*`)
- GraphQL endpoints
- Admin/internal routes

## Architecture

```
webhog/
├── cmd/webhog/          # CLI entry point (Cobra)
│   ├── main.go
│   ├── root.go
│   └── scan.go
├── internal/
│   ├── renderer/        # Page rendering (static & headless)
│   │   ├── renderer.go
│   │   ├── static.go
│   │   └── headless.go
│   ├── scanner/         # Secret detection
│   │   ├── scanner.go
│   │   ├── detectors.go
│   │   └── types.go
│   ├── ui/             # Styled output (Lip Gloss)
│   │   ├── output.go
│   │   └── styles.go
│   └── config/         # Configuration
│       └── config.go
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

- Currently scans single URLs (crawling support coming soon)
- Static mode doesn't execute JavaScript (use `--headless` for SPAs)
- Headless mode requires more resources and time

## Contributing

Contributions are welcome! Areas for improvement:
- Additional secret detectors
- Crawling support (multi-page scanning)
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

Inspired by:
- [TruffleHog Chrome Extension](https://github.com/trufflesecurity/Trufflehog-Chrome-Extension)
- [gowitness](https://github.com/sensepost/gowitness)
