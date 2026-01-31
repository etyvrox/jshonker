# JS Analyzer - CLI Tool

Original Burp Suite Extension by Jensec (https://x.com/_jensec)  
CLI rewrite by 0std1 (https://x.com/0std1)

Command-line tool for analyzing JavaScript files. Extracts endpoints, URLs, secrets, and emails from JS code with noise filtering. Works great with katana.

![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## What's Different from the Original

I rewrote the Burp extension as a CLI tool and added a bunch of stuff:

- **200+ secret patterns** - The original had maybe 20 patterns. I added patterns from TruffleHog so now it catches way more stuff like AWS keys, Stripe tokens, GitHub tokens, Slack tokens, OpenAI keys, Twilio, Mailgun, Heroku, Datadog, Sentry, GitLab, Discord, Vercel, Netlify, and tons of other services. Also detects database URLs, private keys, and generic API key patterns.

- **Analysis modes** - You can focus on specific categories (secrets, endpoints, files, emails) or combine multiple modes. Useful when you only care about certain things.

- **CLI-first** - Built to work with katana and other CLI tools. Auto-detects JSONL format, writes results incrementally, supports JSON output. Good for automation.

## Quick Start

```bash
katana -u https://example.com | jsanalyzer -v
```

That's basically it. jsanalyzer reads URLs from katana (text or JSONL), filters for JS files, downloads them, and analyzes.

## Installation

Install as a package:
```bash
pip install -e .
```

Or manually:
```bash
pip install -r requirements.txt
chmod +x jsanalyzer
```

Then use it: `./jsanalyzer` or `python3 jsanalyzer`

## Usage

Works with katana out of the box. Just pipe katana's output into jsanalyzer:

```bash
# Basic usage
katana -u https://example.com | jsanalyzer

# Verbose output
katana -u https://example.com | jsanalyzer -v

# JSON output
katana -u https://example.com | jsanalyzer -j

# Save to file (writes as it finds stuff)
katana -u https://example.com | jsanalyzer -o results.txt

# JSONL format from katana
katana -u https://example.com -jsonl | jsanalyzer
```

The tool automatically filters for JavaScript files by checking:
- File extension (.js, .mjs, .jsx, etc.)
- URL paths (/js/, /javascript/, /static/js/, etc.)
- Content-Type header (if available in JSONL)

If katana already includes the body in JSONL, it uses that instead of making another HTTP request.

### Analysis Modes

You can focus on specific categories or combine multiple modes:

```bash
# Single mode - only secrets (API keys, tokens, etc.)
katana -u https://example.com | jsanalyzer --mode secrets

# Single mode - only endpoints/URLs
katana -u https://example.com | jsanalyzer --mode endpoints

# Single mode - only file references
katana -u https://example.com | jsanalyzer --mode files

# Single mode - only emails
katana -u https://example.com | jsanalyzer --mode emails

# Multiple modes - comma-separated
katana -u https://example.com | jsanalyzer --mode secrets,emails

# Multiple modes - separate flags
katana -u https://example.com | jsanalyzer --mode secrets --mode emails

# Combine multiple modes
katana -u https://example.com | jsanalyzer --mode secrets,emails,files

# Default: everything (all categories)
katana -u https://example.com | jsanalyzer
```

Available modes: `secrets`, `endpoints`, `files`, `emails`

Modes are useful when you're doing a security audit and only want secrets, or when mapping APIs and only care about endpoints. You can combine modes to focus on multiple categories at once.

### Other Options

```bash
# Single URL
jsanalyzer -u https://example.com/app.js

# Custom timeout and max file size
katana -u https://example.com | jsanalyzer --timeout 30 --max-size 5000000

# Disable auto JS filtering (analyze everything)
katana -u https://example.com | jsanalyzer --no-auto-filter-js

# Read from file
cat urls.txt | jsanalyzer
```

**CLI Options:**
- `-u, --url` - Single URL to analyze (otherwise reads from stdin)
- `-j, --json` - JSON output format
- `-v, --verbose` - Verbose output
- `-o, --output` - Output file (writes incrementally)
- `--mode` - Analysis mode(s). Can be specified multiple times or comma-separated. Options: `secrets`, `endpoints`, `files`, `emails`. Default: all categories. Examples: `--mode secrets` or `--mode secrets,emails` or `--mode secrets --mode emails`
- `--timeout` - Request timeout in seconds (default: 10)
- `--max-size` - Max file size in bytes (default: 10MB)
- `--filter-js-only` - Only analyze URLs that look like JS files
- `--jsonl-input` - Force JSONL input format
- `--auto-filter-js` - Auto-filter JS files from katana JSONL (default: on)
- `--no-auto-filter-js` - Disable auto JS filtering

## What It Finds

### Endpoints
Finds API paths, REST endpoints, OAuth URLs, admin routes, etc. Examples: `/api/v1/users`, `/rest/data`, `/oauth2/token`, `/admin`, `/.well-known/openid-configuration`

### Secrets
200+ detection patterns covering:

- Cloud providers: AWS, GCP, Azure, DigitalOcean, Linode, Vultr, Scaleway, OVH
- Payment: Stripe (all key types), PayPal, Square, Shopify
- Communication: Slack (all token types), Telegram, Twilio, Mailgun, SendGrid, Nexmo
- Dev platforms: GitHub (PAT/OAuth/user/server/refresh), GitLab, Bitbucket, Jira, Confluence
- Monitoring: Datadog, New Relic, Sentry, Rollbar
- Hosting: Heroku, Vercel, Netlify, Cloudflare, Fastly, KeyCDN, MaxCDN, BunnyCDN
- Social: Facebook, Twitter, LinkedIn, Instagram, Pinterest, Reddit, TikTok, Snapchat, Discord, Zoom, Twitch, YouTube
- AI: OpenAI, Google AI
- Storage: Dropbox, OneDrive, Box, Google Drive
- Design: Figma, Sketch, InVision, Zeplin, Marvel, Dribbble, Behance
- Databases: MongoDB, PostgreSQL, MySQL, Redis, RabbitMQ, AWS SQS, S3
- Auth: JWT, OAuth2 tokens, Bearer tokens, generic access tokens
- Private keys: RSA, DSA, EC, OpenSSH, PGP, encrypted keys
- Generic: API keys, secret keys, bearer tokens, authorization headers
- DNS: Route53, DNSimple, Dynu, No-IP, DuckDNS, Namecheap, GoDaddy, Cloudflare
- Other: Firebase, Algolia, Segment, Cloudinary, Imgur, Unsplash, Pexels, Adobe

Most patterns come from TruffleHog. The CLI version has way more than the original Burp extension.

### Files
Detects references to sensitive files like:
- Data: .sql, .csv, .xlsx, .json, .xml, .yaml
- Config: .env, .conf, .ini, .cfg, .config
- Backup: .bak, .backup, .old, .orig
- Certs: .key, .pem, .crt, .p12, .pfx
- Docs: .pdf, .doc, .docx
- Archives: .zip, .tar, .gz
- Scripts: .sh, .bat, .ps1, .py

### Noise Filtering
Automatically filters out XML namespaces, module imports, PDF internal paths, Excel paths, locale files, and crypto library internals to reduce false positives.

## Using the Engine in Your Code

You can import the engine and use it directly:

```python
from js_analyzer_engine import JSAnalyzerEngine

engine = JSAnalyzerEngine()

# Analyze everything
results = engine.analyze(javascript_content)

# Or use modes
secrets = engine.analyze(javascript_content, mode='secrets')
endpoints = engine.analyze(javascript_content, mode='endpoints')
files = engine.analyze(javascript_content, mode='files')

print(results["endpoints"])
print(results["urls"])
print(results["secrets"])
print(results["emails"])
print(results["files"])
```

## File Structure

```
JSAnalyzer/
├── js_analyzer_engine.py   # Analysis engine
├── jsanalyzer              # CLI script
├── setup.py
├── requirements.txt
├── README.md
└── LICENSE
```

## Contributing

Feel free to:
- Add more secret patterns
- Improve noise filtering
- Add endpoint patterns
- Report bugs

## License

MIT License

## Credits

Inspired by:
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder) - Endpoint detection
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret patterns

## Authors

- Original Burp Suite Extension: Jenish Sojitra (https://x.com/_jensec)
- CLI Rewrite: 0std1 (https://x.com/0std1)
