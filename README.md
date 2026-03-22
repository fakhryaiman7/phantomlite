# PhantomLite

A lightweight, free, and self-contained CLI tool for bug bounty reconnaissance.

## Features

- **Subdomain Discovery** - Uses crt.sh, HackerTarget, RapidDNS, and more
- **Live Host Checking** - Async HTTP checks with status detection
- **Web Crawling** - Extracts links, forms, and parameters
- **Directory Fuzzing** - Built-in wordlist for common paths
- **Vulnerability Checks** - Basic checks for XSS, open redirect, missing headers
- **Target Analysis** - Scores and prioritizes targets
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

Run reconnaissance:
```bash
python cli.py recon example.com
python cli.py recon example.com --fast
python cli.py recon example.com --depth 3 --threads 30
```

Individual modules:
```bash
python cli.py subdomains example.com
python cli.py livecheck domains.txt
python cli.py crawl https://example.com
python cli.py fuzz https://example.com
```

Commands:
- `recon` - Full reconnaissance scan
- `subdomains` - Discover subdomains
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
