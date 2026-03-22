# PhantomLite

A lightweight, free, and self-contained CLI tool for bug bounty reconnaissance.

## Features

- **Subdomain Discovery** - Uses crt.sh, HackerTarget, RapidDNS, and more
- **Wayback Machine Integration**: Discover historical URLs and endpoints.
- **Port Scanning**: Detect open ports and services on live hosts.
- **Subdomain Takeover Detection**: Identify vulnerable CNAME records.
- **Cloud Storage Scanner**: Locate exposed S3, Azure, and GCP buckets.
- **Web Crawling** - Extracts links, forms, and parameters
- **Directory Fuzzing** - Built-in wordlist for common paths
- **Dynamic Vuln Scanner**: Automated XSS and SQL Injection detection.
- **Template-based Vuln Scanner**: Automated checks for common misconfigurations.
- **Interactive HTML Reports**: Professional dashboard named after the target.
- **Advanced Scoring**: Host/URL prioritization based on risk.
- **Auto-Setup** - Automatically installs dependencies on first run

## Requirements

- Python 3.10+
- No external tools required

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/fakhryaiman7/phantomlite.git
   cd phantomlite
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   ```

3. **Activate the virtual environment:**
   - **Linux/macOS:**
     ```bash
     source venv/bin/activate
     ```
   - **Windows:**
     ```powershell
     .\venv\Scripts\activate
     ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

# Run full reconnaissance (Generates HTML Report)
python3 cli.py recon example.com

# Only check subdomains
python3 cli.py subdomains example.com

# Only check for takeover
python3 cli.py takeover subdomains.txt

# Only scan for cloud buckets
python3 cli.py cloudscan example.com

# Only scan for XSS/SQLi (requires endpoints file)
python3 cli.py xss endpoints.json
python3 cli.py sqli endpoints.json

Run reconnaissance:
```bash
python cli.py recon example.com --fast
python cli.py recon example.com --depth 3 --threads 30
```

Individual modules:
```bash
python3 cli.py subdomains example.com
python3 cli.py wayback example.com
python3 cli.py portscan example.com
python3 cli.py livecheck domains.txt
python3 cli.py crawl https://example.com
python3 cli.py fuzz https://example.com
```

Commands:
- `recon` - Full automated reconnaissance scan (includes all modules)
- `subdomains` - Discover subdomains
- `wayback` - Discover historical URLs from Archive.org
- `portscan` - Scan for common open ports
- `livecheck` - Check live hosts
- `crawl` - Crawl a website
- `fuzz` - Directory fuzzing
- `version` - Show version
- `help` - Show help

## Options

```
--fast          Fast mode (reduced scanning)
--no-bruteforce Skip subdomain bruteforcing
--no-cache      Disable result caching
-o, --output    Output directory
-d, --depth     Crawl depth (1-5)
-p, --pages     Max pages to crawl
-t, --threads   Concurrent threads
-r, --rate-limit  Requests per second
-v, --verbose   Verbose output
```

## Auto-Setup

On first run, the tool automatically:
1. Creates a virtual environment (venv)
2. Installs all dependencies from requirements.txt

Users only need to run:
```bash
python cli.py recon example.com
```

## Output

Results are saved to:
- `results/<domain>_report.json` - Full JSON report
- `results/<domain>_cache.json` - Cached results

## Safety

**:warning: WARNING: Use only on targets you have permission to test!**

The tool includes:
- Rate limiting (default: 15 req/s)
- Request throttling
- No aggressive scanning

## License

Free to use for educational and authorized testing purposes only.
