# Webhog

A headless web secret scanner CLI tool built in Go. Webhog scans web pages for exposed secrets, API keys, tokens, database credentials, and interesting endpoints.

Inspired by the [TruffleHog browser extension](https://github.com/trufflesecurity/Trufflehog-Chrome-Extension) and [gowitness](https://github.com/sensepost/gowitness)'s headless browser approach.

## Features

- **Dual Scanning Modes**
  - **Static Mode** (default): Fast HTTP-only scanning without JavaScript execution
  - **Headless Mode**: Full browser rendering for JavaScript-heavy SPAs using [go-rod](https://github.com/go-rod/rod).
    Every byte comes through Chrome's own network stack, including external
    scripts and runtime `fetch`/XHR responses, so hosts behind bot management
    that reject non-browser TLS fingerprints still yield their JavaScript.
    One Chromium process serves the whole run; each target gets its own
    incognito context.

- **Auto-Download Chromium**: When using headless mode, Chromium is automatically downloaded if not found (cached for future use)

- **Detection**
  - About a hundred detectors: cloud providers (AWS, Azure, DigitalOcean,
    Vault, Pulumi, Databricks, PlanetScale, Doppler), Google (API keys, OAuth
    client secrets and IDs, refresh tokens, service accounts, Firebase
    configs and database URLs), payments (Stripe keys and webhook secrets,
    Braintree, Square), source control and registries (GitHub classic,
    fine-grained and app tokens, GitLab, npm, PyPI, Atlassian), AI providers
    (OpenAI, Anthropic, Hugging Face, Groq, Perplexity, Replicate), messaging
    (Slack tokens and webhooks, Discord, Telegram, Twilio, SendGrid, Mailgun,
    Mailchimp, Postmark, Resend, Twitter), SaaS (Shopify, Notion, Linear,
    Airtable, Supabase, Mapbox, Algolia, Sentry, Datadog, Cloudflare, New
    Relic, Grafana, LaunchDarkly, Dropbox, Postman, Contentful, Heroku), JWTs,
    private keys, passwords in URLs, connection strings, and four Generic
    rules. `webhog detectors` lists them.
  - **Public by design**: shapes a provider intends to ship to browsers
    (Stripe publishable keys, Datadog client tokens, Sentry DSNs, Mapbox `pk.`
    tokens, OAuth client IDs) are reported and labelled `public`, not dropped
    and not mistaken for leaks.
  - **Offline enrichment**: with no network traffic, a JWT's algorithm,
    issuer, subject, role, scope, issue and expiry times and expired flag
    (unsigned and Supabase `service_role` tokens called out); the AWS account
    ID decoded from an access key ID; Stripe key kind and mode; Slack token
    family; a Firebase config's project, bucket and database URL.
  - **Noise control**: a Generic value must look like a credential (digits
    and a spread character distribution, no placeholder words), a Generic row
    that repeats a named match is dropped, and `--generic-cap` keeps a bundle
    with hundreds of `token:` assignments from producing hundreds of rows.
  - `--detectors` / `--exclude-detectors` select by name or type.

- **Source Maps**
  - Follows each script's `sourceMappingURL` comment (inline `data:` maps
    included) and, when there is none, probes `<script>.map`. A reachable map
    is reported as a `Source Map Exposed` finding, and the original sources
    it embeds are mined under their own file names, so a key in
    `src/config.ts` is found where the developer wrote it. Vendor sources
    under `node_modules` are counted but not mined unless asked.

- **Lazily Loaded Chunks**
  - Reconstructs chunk filenames from a webpack 4 or 5 runtime, reads Vite's
    dependency array, fetches a Next.js build manifest from the build id,
    follows dynamic `import()` literals, `modulepreload` links,
    `importScripts` and a service worker's precache manifest. Route code the
    landing page never loads is scanned anyway.

- **Page State** (headless and auto)
  - After each page settles, localStorage, sessionStorage, the browser's
    cookies (HttpOnly ones included) and the framework globals that carry
    server state and runtime configuration (`__NEXT_DATA__`, `__NUXT__`,
    `__INITIAL_STATE__`, `__APP_CONFIG__`, `__ENV__`, `firebaseConfig` and
    others) are read and scanned. Values an app writes at runtime are in no
    response body.

- **Historical Scripts** (`--wayback`)
  - The Wayback Machine's index is asked for the scripts it captured under
    the target's host; the ones the live page no longer loads are fetched,
    live or from the archive. Old bundles carry keys that were rotated out of
    the current ones.

- **Cloud Storage and Exposed Files**
  - Bucket references in either URL style (S3, Google Cloud Storage, Azure
    Blob) are findings; `--verify` asks the service for one object and
    reports whether the bucket lists publicly or is unclaimed.
    `--probe-exposures` seeds `.env`, `.git/config`, API specifications and
    the Spring actuator environment, with detectors that recognise each.

- **Third Party and Deduplication**
  - A script served from another registered domain is labelled
    `third_party`; `--first-party-only` skips mining it. A byte-identical body
    is scanned once per target however many URLs or pages serve it.

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
  - All checks are read-only (identity, status and listing endpoints; nothing is written)
  - About forty providers, and what the provider says about the credential
    rides on the finding: GitHub token scopes and login, SendGrid and Airtable
    scopes, the Slack workspace, account identities
  - Google API keys are probed for the APIs they are enabled on (Generative
    Language, Geocoding, Static Maps, YouTube) and whether they are
    referrer-restricted
  - Firebase: open database reads, open Firestore reads, open storage listing
  - AWS access key and secret found together are verified as a pair over STS
    `GetCallerIdentity`, which names the account and principal

- **Compare Against an Earlier Run**
  - `--baseline` takes a previous output and marks findings it did not hold
    as `new`; `--only-new` lists only those. Every report carries the hash of
    each fetched script, and against a baseline the count of scripts added,
    changed and removed.

- **Auto Mode**
  - `--mode auto` fetches statically and switches a target to the browser
    only when the static answer looks like bot management, so a list of
    hosts costs a browser only where one is needed.

- **Technology Detection (Wappalyzer)**
  - Identifies CMS, frameworks, servers, and more using [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo)

- **Progressive Output**
  - **Streaming Results**: Findings are displayed immediately as they are found
  - **Smart Labels**: Context-aware labels (e.g., "URL" for endpoints, "Secret" for tokens)
  - **File Output**: Save clean, plain-text results to a file with `-o`/`--output`
  - **JSON Lines**: `--jsonl` writes one report per target the moment it
    completes, so a run that is killed part-way still leaves every finished
    target on disk

- **Rate Limiting and Concurrency**
  - `--rate-limit` / `--delay` cap every request across the whole run,
    including the script and XHR loads the browser makes on its own, so it
    can honor a program's request ceiling like the rest of a recon pipeline
  - `--concurrency` renders several pages of a target at once and
    `--parallel` scans several targets at once, always under the same ceiling

- **Beautiful Output**
  - Styled terminal output using [Lip Gloss](https://github.com/charmbracelet/lipgloss)
  - JSON output for automation and CI/CD integration

## Installation

### With `go install`

```bash
go install github.com/emancipat3r/webhog/cmd/webhog@latest
```

### From Source

```bash
git clone https://github.com/emancipat3r/webhog
cd webhog
make build        # stamps the version and commit into the binary
./webhog --version
```

`webhog --version` and the `webhog` field of every JSON report identify the
build that produced a result. `make build` stamps them from git; a plain
`go build` or `go install ...@vX.Y.Z` falls back to the module version and VCS
revision Go embeds.

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

Headless mode navigates with a real Chromium and reads external scripts, and
runtime `fetch`/XHR responses, out of the responses the browser itself
received. Nothing is re-fetched with Go's HTTP client, whose TLS and HTTP/2
fingerprint is what Cloudflare-class bot management rejects before it reads a
single header. A script the server refuses is kept anyway (error pages leak)
and counted under `js_refused`, so a page whose scripts were all blocked is
distinguishable from a page with none.

One browser process is launched per run, on first use, and reused for every
page. Each target is rendered in its own incognito context, so cookies and
storage never bleed between hosts. After `window.onload` the page gets
`--dom-wait` (default 3s) to settle before it is read; raise it for SPAs that
load slowly, lower it for speed.

### Auto Mode

```bash
webhog scan --mode auto --list hosts.txt
```

Each target is fetched statically first. When the answer looks like bot
management (a 403, 429 or 503 with a small body or with every script
refused, or a body carrying a Cloudflare, Akamai, PerimeterX, DataDome,
Imperva, Distil or Kasada marker) that target switches to the browser for the
rest of its pages. A target that was never blocked never starts the browser.
The switch is printed to stderr.

### Source Maps and Chunks

Both are on by default and cost extra requests per script, paced by the same
limiter as everything else:

```bash
webhog scan https://app.example.com                      # maps followed and probed, chunks fetched
webhog scan --probe-source-maps=false https://app.example.com   # follow comments only
webhog scan --chunks=false --source-maps=false https://app.example.com
webhog scan --vendor-sources https://app.example.com     # mine node_modules sources inside maps too
```

A reachable map is a `Source Map Exposed` finding on the script, with the
number of sources, how many carry content, and whether the map was named by
the script or found by probing. Findings inside the sources have a path of
`<map URL>#<source file>`. The summary reports `Source Maps: 2 of 7 tried`
and `JS Chunks: 41`, and `--max-chunks` (default 200) and `--max-map-size`
(default 64 MiB) bound the work.

### Compare Against an Earlier Run

```bash
webhog scan --list hosts.txt --jsonl -o monday.jsonl
webhog scan --list hosts.txt --jsonl -o tuesday.jsonl --baseline monday.jsonl --only-new
```

The baseline is indexed by the registered domain of each seed. Findings it
did not hold are marked `new: true` and counted in `new_findings`; with
`--only-new` the others are left out of the list while the summary still
counts them. Every report lists its fetched scripts with a SHA-256, and
against a baseline `script_changes` counts those added, changed and removed,
which usually moves before any finding does. A target the baseline never saw
is not marked at all.

### Choose Detectors

```bash
webhog detectors                                  # the table: name, type, public, verifiable
webhog scan --detectors secret,config https://example.com
webhog scan --exclude-detectors generic,"HTTP URL" https://example.com
```

Names are matched case-insensitively; the words `secret`, `config`,
`endpoint` and `generic` select a whole type. An unknown name is an error
before any request is made.

### Historical Scripts from the Wayback Machine

```bash
webhog scan --wayback https://app.example.com              # fetch the live URLs the index names
webhog scan --wayback --wayback-archived https://app.example.com   # fetch the archived copies instead
```

The CDX index is asked once per target for JavaScript captured under the
host. Scripts the live page already loads are skipped; the rest are fetched
from the host (a script that is gone is a 404 blob, counted as refused) or,
with `--wayback-archived`, from `web.archive.org`, in which case the target
sees no request for them. Findings carry the original URL, with
`#archived-<timestamp>` appended for archive copies. `--max-wayback`
(default 100) caps the fetches. The index query goes to archive.org, not
the target.

### Crawl One Record per Template

`--shapes-once` (default on) treats `/item/1` and `/item/2` as one path
shape (numeric, UUID and long hex segments are placeholders, query values
are ignored) and crawls the first URL of each. A template loads the same
scripts whichever record it shows, so the page budget goes to different
templates instead. The summary counts the candidates skipped. Pass
`--shapes-once=false` to crawl every URL.

### Probe Runtime Configuration

```bash
webhog scan --probe-config https://app.example.com
```

Adds the well-known runtime configuration paths (`/config.json`, `/env.js`,
`/environment.json`, their `assets/` and `static/` variants, `/api/config`,
the OpenID configuration) as seeds. Single-page apps fetch these after load,
so their contents are in no bundle.

### Redact Tokens

```bash
webhog scan --redact --json https://example.com
```

Masks every token in text and JSON output, keeping the first and last four
characters so two reports can still be matched up.

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
50-host list is 50 scoped crawls). A host that cannot be scanned at all still
gets a report, with an `error` field and nothing else, so the output shows
coverage rather than just findings; the run continues and the process exits
non-zero only when no target could be scanned. With `--json`, one target emits
a single object and many targets emit an array.

### Stream Results as JSON Lines

```bash
webhog scan --list hosts.txt --jsonl -o results.jsonl
```

`--jsonl` writes one compact JSON report per line, per target, the moment that
target completes. Unlike `--json` (a single array that can only be written
when the run ends), a run that is killed by a timeout or an OOM leaves every
completed target readable in the file. Text output to `-o` is also appended per
target.

### Rate Limiting and Concurrency

```bash
webhog scan --list hosts.txt --rate-limit 10 --concurrency 4 --parallel 2
```

- `--rate-limit N` caps requests at N per second across the **whole run**:
  page fetches, script fetches in static mode, `robots.txt`, source maps,
  chunks, headless navigations, and the script and XHR loads the browser
  makes during a navigation (held at the request stage until the limiter
  grants a slot), over every worker and target. `--delay D` forces a minimum
  spacing instead; the stricter of the two wins.
- `--concurrency N` (default 4) renders up to N pages of one target at once.
- `--parallel N` (default 1) scans up to N targets at once. Live text output
  is buffered per target and printed whole when it completes, so reports never
  interleave; JSON Lines and file output stream as before.

Raising either knob never raises the request rate above the ceiling, because
the limiter sits underneath all of them.

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
not. The anchor is the seed **as given** and never moves: if a seed redirects
to another domain (an SSO front such as `accounts.google.com` is the common
case), the landing page is fetched and scanned because that is where the seed
leads, but none of its links are crawled, not even ones pointing back into
scope (an SSO login page carries `continue=` URLs for the in-scope app, and
following them only bounces through the same front again). The report records
this with
`redirected_off_scope: true`, carries the original target in `seed` alongside
the post-redirect `url`, and a warning is printed. Pass `--same-domain=false`
to follow off-domain links as well (noisier).
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
> endpoints (e.g. GitHub `/user`, Stripe `/v1/balance`, Slack `auth.test`,
> STS `GetCallerIdentity`). Only run it against targets you are authorized to
> test. The Google Geocoding and Static Maps probes are billable to the key's
> owner at a fraction of a cent each.

What the provider reports about the credential is recorded on the finding's
`details`: GitHub's `scopes` header and the login, SendGrid and Airtable
scopes, the Slack team and workspace URL, the email or username behind an
identity endpoint, the APIs a Google key is enabled for (`apis_enabled`,
`apis_denied`, `restricted`), whether a Firebase project allows
unauthenticated reads (`firestore_open`, `storage_listing_open`,
`rtdb_open_read`), and the account and ARN an AWS pair belongs to.
Public-by-design shapes are not sent anywhere.

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
- `--mode`: `static` (HTTP only, default), `headless` (browser for every page), or `auto` (HTTP first, browser for a target whose answer looks like bot management)
- `--headless`: Same as `--mode headless`
- `--timeout`: Page load timeout (default: 30s)
- `--dom-wait`: Headless only. Time to let a page settle after load before reading it (default: 3s; 0 = none)

**Pacing:**
- `--rate-limit`: Maximum requests per second webhog originates across the whole run (default: 0 = unlimited)
- `--delay`: Minimum time between requests, e.g. `500ms` (default: 0)
- `-c, --concurrency`: Pages rendered at once within a target (default: 4)
- `-p, --parallel`: Targets scanned at once (default: 1)

**Input:**
- `-l, --list`: Read targets (one per line) from a file. Targets may also be passed as arguments or piped on stdin; bare hostnames default to `https://`.

**Output:**
- `-o, --output`: Write results to file
- `--redact`: Mask every token in text and JSON output
- `--baseline`: Earlier webhog output to compare against; findings it did not hold are marked `new`
- `--only-new`: With `--baseline`, report only new findings
- `--json`: Output results as JSON (one object for a single target, an array for many, written when the run ends)
- `--jsonl`: Output results as JSON Lines, one report per line written as each target completes
- `--quiet`: Minimal output
- `--plain`: Disable styled output

**Crawling:**
- `--max-depth`: Maximum crawl depth (default: 0 = single URL only). At each page, both `<a href>` anchors and endpoints discovered in JS/HTML are followed breadth-first.
- `--max-pages`: Maximum number of pages to crawl (default: 200; 0 = unlimited)
- `--same-domain`: Restrict the crawl to the seed's registered (apex) domain (default: true; e.g. `api.example.com` and `www.example.com` both count for a seed on `example.com`). Set `--same-domain=false` to follow off-domain links too.
- `--robots`: Use `robots.txt` as an enumeration source — scan its `Disallow`/`Allow` paths and `Sitemap:` URLs (default: false). Does **not** honor crawl restrictions; authorized targets only.
- `--probe-config`: Also scan the well-known runtime configuration paths as seeds (default: false)
- `--probe-exposures`: Also scan `.env`, `.git/config`, API specification and actuator paths as seeds (default: false)
- `--shapes-once`: Crawl one URL per path shape (default: true)
- `--capture-state`: Headless and auto: read storages, cookies and framework globals after each page settles (default: true)

**Expansion:**
- `--source-maps`: Follow `sourceMappingURL` comments and mine the sources a map embeds (default: true)
- `--probe-source-maps`: When a script names no map, try `<script>.map` (default: true)
- `--vendor-sources`: Also mine `node_modules` sources embedded in maps (default: false)
- `--max-map-size`: Largest source map to download, in bytes (default: 64 MiB)
- `--chunks`: Discover lazily loaded chunks from the bundler runtime and fetch them (default: true)
- `--max-chunks`: Chunks to fetch per target at most (default: 200)
- `--wayback`: Fetch the scripts the Wayback Machine captured under the host that the live page no longer loads (default: false)
- `--wayback-archived`: With `--wayback`, fetch the archived copies instead of the live URLs (default: false)
- `--max-wayback`: Historical scripts to fetch per target at most (default: 100)

**Detection:**
- `--verify`: Validate detected secrets against provider APIs (read-only). Makes outbound requests using the discovered credentials — only use against targets you're authorized to test.
- `--detectors`: Run only these detectors (names or the type words `secret`, `config`, `endpoint`, `generic`)
- `--exclude-detectors`: Skip these detectors
- `--generic-cap`: Matches one Generic detector may report from one file before the rest are counted as `overflow` (default: 20; -1 = no cap)
- `--first-party-only`: Mine only resources served from the target's registered domain
- `--include-entropy`: Enable entropy-based detection
- `--min-entropy`: Minimum entropy threshold (default: 4.5)
- `--min-length`: Minimum token length for detection (default: 20)

## Detection Rules

`webhog detectors` prints the full table. Detector names are part of the
output contract: consumers match on them, so they do not change.

### Secrets
Cloud (AWS access keys, secrets, MWS, AppSync; Azure storage keys;
DigitalOcean; Vault; Pulumi; Databricks; PlanetScale; Doppler), Google (API
keys, OAuth client secrets, refresh tokens, service accounts), Facebook,
Stripe (secret, restricted, webhook signing), Braintree, Square, GitHub
(classic, fine-grained, OAuth, app, legacy), GitLab, npm, PyPI, Atlassian,
OpenAI, Anthropic, Hugging Face, Groq, Perplexity, Replicate, Slack (tokens,
app-level, webhooks), Discord (bot tokens, webhooks), Telegram, Twilio,
SendGrid, Mailgun, Mailchimp, Postmark, Resend, Twitter, Heroku, Shopify,
Notion, Linear, Airtable, Supabase, Mapbox, Algolia, Cloudflare, New Relic,
Grafana, LaunchDarkly, Dropbox, Postman, Contentful, age, JWTs, private keys
(PEM, any kind), passwords in URLs.

### Public by design (labelled, not dropped)
Stripe publishable keys, Google OAuth client IDs, Twilio account SIDs,
Supabase publishable keys, Mapbox `pk.` tokens, Sentry DSNs, Datadog client
tokens, Cloudflare beacon tokens, New Relic browser keys.

### Generic
API key, token, secret and password assignments whose value looks like a
credential.

### Configuration
Firebase configs and database URLs; connection strings (PostgreSQL, MySQL,
MongoDB, Redis, AMQP, SQL Server); S3, Google Cloud Storage and Azure Blob
references; exposed source maps, git configs, API specifications and Spring
actuator environments.

### Endpoints
HTTP/HTTPS URLs and relative paths, WebSocket URLs, API endpoints
(`/api/*`), GraphQL endpoints, admin and internal paths.

## Report Fields

Each finding carries `detector`, `type`, `path`, `line`, `snippet`, `token`,
`loaded_from` (the page that referenced the resource, or `null` for the page
itself), and when applicable `public`, `third_party`, `details` (offline
enrichment and what verification learned), `verification`, `new` (against a
baseline) and `overflow` (matches not listed because of `--generic-cap`).

Each report carries the counters `pages_crawled`, `js_blobs`, `js_refused`,
`js_deduped`, `js_chunks`, `js_chunks_capped`, `source_maps_tried`,
`source_maps`, `wayback_scripts`, `pages_skipped_same_shape`, the `scripts` list (path, source, status, SHA-256, size,
third party), and against a baseline `new_findings` and `script_changes`.

## Architecture

```
webhog/
├── cmd/webhog/          # CLI entry point (Cobra)
│   ├── main.go
│   ├── root.go
│   ├── scan.go
│   └── detectors.go     # `webhog detectors`
├── internal/
│   ├── renderer/        # Page rendering (static, headless, auto)
│   ├── crawler/         # Breadth-first multi-page crawling (worker pool)
│   ├── expand/          # Source maps and lazily loaded chunks
│   ├── ratelimit/       # Process-wide request pacing
│   ├── version/         # Build version and commit
│   ├── scanner/         # Detector table, noise control, offline enrichment
│   ├── verifier/        # Live credential validation (--verify)
│   ├── baseline/        # Comparison against an earlier run
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

- Crawling follows `<a href>` anchors and endpoints found via the scanner's regexes in JS/HTML, but not URLs assembled dynamically at runtime (e.g. string-concatenated paths). Headless mode does pick up scripts and `fetch`/XHR responses the page requests at runtime.
- Chunk and source map fetches use Go's HTTP client even in headless mode, so a host whose bot management rejects non-browser clients may refuse them; the refusal is counted.
- Chunk templates are reconstructed from the common webpack, Vite and Next.js shapes; an unusual runtime yields nothing rather than something wrong.
- Static mode doesn't execute JavaScript (use `--headless` or `--mode auto` for SPAs)
- Headless mode requires more resources and time

## Contributing

Contributions are welcome! Areas for improvement:
- Additional secret detectors and verifiers
- Custom detector rules

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
