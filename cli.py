"""
PhantomLite CLI Module
Command-line interface using Typer.
"""
import typer
from typing import Optional
from pathlib import Path
import os
from rich.console import Console
from rich.panel import Panel
import asyncio

app = typer.Typer(
    name="PhantomLite",
    help="Lightweight Bug Bounty Reconnaissance Tool",
    add_completion=False
)

console = Console()


@app.command()
def recon(
    domain: str = typer.Argument(..., help="Target domain to scan"),
    output: Optional[str] = typer.Option("results", "-o", "--output", help="Output directory"),
    depth: int = typer.Option(2, "-d", "--depth", help="Crawl depth (1-5)", min=1, max=5),
    pages: int = typer.Option(50, "-p", "--pages", help="Max pages to crawl", min=10, max=200),
    threads: int = typer.Option(20, "-t", "--threads", help="Concurrent threads", min=5, max=50),
    rate_limit: float = typer.Option(15.0, "-r", "--rate-limit", help="Requests per second", min=5.0, max=50.0),
    fast: bool = typer.Option(False, "--fast", help="Fast mode (reduced scanning)"),
    no_bruteforce: bool = typer.Option(False, "--no-bruteforce", help="Skip subdomain bruteforcing"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable result caching"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
):
    """
    Run full reconnaissance on a target domain.
    """
    from core.pipeline import run_recon
    from utils.logger import get_logger
    
    logger = get_logger()
    
    if verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
    
    console.print(Panel(
        "[bold cyan]PhantomLite[/bold cyan] - Bug Bounty Reconnaissance Tool\n"
        "[dim]Use only on authorized targets[/dim]",
        border_style="cyan"
    ))
    
    console.print(f"\n[yellow]WARNING: Use only on targets you have permission to test![/yellow]\n")
    console.print(f"[cyan]Target:[/cyan] {domain}")
    console.print(f"[cyan]Output:[/cyan] {output}")
    console.print(f"[cyan]Depth:[/cyan] {depth}")
    console.print(f"[cyan]Fast Mode:[/cyan] {'Enabled' if fast else 'Disabled'}\n")
    
    try:
        results = asyncio.run(run_recon(
            domain=domain,
            logger=logger,
            output_dir=output,
            max_depth=depth,
            max_pages=pages,
            rate_limit=rate_limit,
            bruteforce=not no_bruteforce,
            use_cache=not no_cache,
            fast=fast
        ))
        
        console.print("\n[bold green]+ Scan completed successfully![/bold green]\n")
        
        stats = results.get('statistics', {}) if 'statistics' in results else {}
        if not stats:
            stats = {
                'subdomains_found': len(results.get('subdomains', [])),
                'live_hosts': len(results.get('live_hosts', [])),
                'pages_crawled': len(results.get('crawl_results', [])),
                'vuln_findings': len(results.get('vuln_findings', [])),
                'high_value_targets': len([t for t in results.get('scored_targets', []) if t.get('score', 0) >= 40])
            }
        
        console.print(Panel(
            f"[green]Subdomains:[/green] {stats.get('subdomains_found', 0)}\n"
            f"[green]Live Hosts:[/green] {stats.get('live_hosts', 0)}\n"
            f"[green]Pages Crawled:[/green] {stats.get('pages_crawled', 0)}\n"
            f"[green]Vulnerabilities:[/green] {stats.get('vuln_findings', 0)}\n"
            f"[yellow]High Value Targets:[/yellow] {stats.get('high_value_targets', 0)}",
            title="[bold]Scan Statistics[/bold]",
            border_style="green"
        ))
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"\n[red bold]Error:[/red bold] {str(e)}")
        raise typer.Exit(code=1)


@app.command()
def subdomains(
    domain: str = typer.Argument(..., help="Target domain"),
    bruteforce: bool = typer.Option(True, "--bruteforce/--no-bruteforce", help="Enable bruteforce"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file"),
):
    """
    Discover subdomains for a target.
    """
    from modules.subdomain import find_subdomains
    from utils.logger import get_logger
    
    logger = get_logger()
    logger.header(f"Subdomain Discovery - {domain}")
    
    try:
        results = asyncio.run(find_subdomains(domain, logger=logger, bruteforce=bruteforce))
        
        console.print(f"\n[bold green]Found {len(results)} subdomains:[/bold green]\n")
        
        for subdomain in results:
            console.print(f"  [cyan]+[/cyan] {subdomain}")
        
        if output:
            with open(output, 'w') as f:
                f.write('\n'.join(results))
            console.print(f"\n[green]Results saved to {output}[/green]")
            
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@app.command()
def livecheck(
    domains: str = typer.Argument(..., help="Comma-separated list of domains or file path"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file"),
):
    """
    Check which subdomains are live.
    """
    from modules.live import check_live_hosts
    from utils.logger import get_logger
    
    logger = get_logger()
    
    domain_list = []
    if Path(domains).exists():
        with open(domains) as f:
            domain_list = [line.strip() for line in f if line.strip()]
    else:
        domain_list = [d.strip() for d in domains.split(',')]
    
    logger.header(f"Live Host Check - {len(domain_list)} domains")
    
    try:
        results = asyncio.run(check_live_hosts(domain_list, logger=logger))
        
        console.print(f"\n[bold green]Found {len(results)} live hosts:[/bold green]\n")
        
        console.print("{:<60} {:<10} {}".format("[cyan]URL[/cyan]", "[yellow]Status[/yellow]", "[green]Title[/green]"))
        console.print("-" * 100)
        
        for host in results:
            title = (host.title or 'N/A')[:30]
            console.print("{:<60} {:<10} {}".format(host.url[:60], host.status, title))
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@app.command()
def crawl(
    url: str = typer.Argument(..., help="Starting URL"),
    depth: int = typer.Option(2, "-d", "--depth", help="Crawl depth", min=1, max=5),
    max_pages: int = typer.Option(50, "-p", "--pages", help="Max pages"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file"),
):
    """
    Crawl a website and extract links, forms, and parameters.
    """
    from modules.crawler import crawl_site
    from utils.logger import get_logger
    
    logger = get_logger()
    logger.header(f"Web Crawler - {url}")
    
    try:
        results = asyncio.run(crawl_site(url, logger=logger, max_depth=depth, max_pages=max_pages))
        
        all_links = set()
        all_forms = []
        all_params = set()
        
        for r in results:
            all_links.update(r.links)
            all_forms.extend(r.forms)
            all_params.update(r.parameters)
        
        console.print(f"\n[bold green]Crawl Complete:[/bold green]\n")
        console.print(f"  [cyan]Pages:[/cyan] {len(results)}")
        console.print(f"  [cyan]Links:[/cyan] {len(all_links)}")
        console.print(f"  [cyan]Forms:[/cyan] {len(all_forms)}")
        console.print(f"  [cyan]Parameters:[/cyan] {len(all_params)}")
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@app.command()
def fuzz(
    url: str = typer.Argument(..., help="Base URL to fuzz"),
    wordlist: Optional[str] = typer.Option(None, "-w", "--wordlist", help="Custom wordlist"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file"),
):
    """
    Fuzz directories and files on a web server.
    """
    from modules.fuzz import fuzz_directories
    from utils.logger import get_logger
    
    logger = get_logger()
    logger.header(f"Directory Fuzzing - {url}")
    
    try:
        results = asyncio.run(fuzz_directories(url, logger=logger))
        
        interesting = [r for r in results if r.status in [200, 401, 403] or r.is_sensitive]
        
        console.print(f"\n[bold green]Found {len(results)} paths, {len(interesting)} interesting:[/bold green]\n")
        
        if interesting:
            console.print("{:<60} {:<10} {}".format("[cyan]URL[/cyan]", "[yellow]Status[/cyan]", "[green]Length[/green]"))
            console.print("-" * 80)
            
            for r in interesting[:20]:
                console.print("{:<60} {:<10} {}".format(r.url[:60], r.status, r.content_length))
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@app.command()
def wayback(
    domain: str = typer.Argument(..., help="Target domain"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file"),
):
    """
    Discover historical URLs using Wayback Machine.
    """
    from modules.wayback import find_wayback_urls
    from utils.logger import get_logger
    
    logger = get_logger()
    logger.header(f"Wayback Discovery - {domain}")
    
    try:
        results = asyncio.run(find_wayback_urls(domain, logger=logger))
        
        console.print(f"\n[bold green]Found {len(results)} historical URLs:[/bold green]\n")
        
        for url in results[:50]:
            console.print(f"  [cyan]+[/cyan] {url}")
            
        if len(results) > 50:
            console.print(f"\n[dim]... and {len(results) - 50} more[/dim]")
        
        if output:
            with open(output, 'w') as f:
                f.write('\n'.join(results))
            console.print(f"\n[green]Results saved to {output}[/green]")
            
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@app.command()
def portscan(
    host: str = typer.Argument(..., help="Target host or IP"),
    ports: Optional[str] = typer.Option(None, "-p", "--ports", help="Comma-separated ports"),
):
    """
    Scan for common open ports.
    """
    from modules.portscan import scan_ports
    from utils.logger import get_logger
    
    logger = get_logger()
    logger.header(f"Port Scan - {host}")
    
    port_list = None
    if ports:
        port_list = [int(p.strip()) for p in ports.split(',')]
    
    try:
        results = asyncio.run(scan_ports(host, ports=port_list, logger=logger))
        
        if not results:
            console.print("\n[yellow]No open ports found[/yellow]\n")
            return
            
        console.print(f"\n[bold green]Found {len(results)} open ports:[/bold green]\n")
        
        console.print("{:<10} {:<15} {:<10} {}".format("[cyan]Port[/cyan]", "[yellow]Service[/yellow]", "[green]State[/green]", "[dim]Banner[/dim]"))
        console.print("-" * 60)
        
        for r in results:
            console.print("{:<10} {:<15} {:<10} {}".format(r.port, r.service, r.state, r.banner[:30]))
            
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@app.command()
def takeover(
    domain: str = typer.Argument(..., help="Target domain or file with subdomains"),
):
    """
    Check for potential subdomain takeovers.
    """
    from modules.takeover import run_takeover_check
    from utils.logger import get_logger
    
    logger = get_logger()
    logger.header(f"Takeover Check - {domain}")
    
    # Check if domain is a file or a single domain
    if os.path.isfile(domain):
        with open(domain, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [domain]
        
    try:
        results = asyncio.run(run_takeover_check(targets, logger=logger))
        if not results:
            console.print("\n[yellow]No potential takeovers found.[/yellow]\n")
            return
            
        console.print(f"\n[bold red]Found {len(results)} potential takeovers![/bold red]\n")
        for r in results:
            console.print(f"[red]![/red] {r.url} -> {r.description}")
            
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@app.command(name='cloudscan')
def cloud_scan(domain: str = typer.Argument(..., help="Domain to scan for cloud buckets")):
    """Scan for exposed cloud storage buckets (S3/Azure/GCP)"""
    from modules.cloud import run_cloud_scan
        console.print(f"[red]Error: {e}[/red]")


@app.command()
def version():
    """
    Show PhantomLite version.
    """
    console.print(Panel(
        "[bold cyan]PhantomLite v1.0.0[/bold cyan]\n"
        "[dim]Lightweight Bug Bounty Reconnaissance Tool[/dim]",
        border_style="cyan"
    ))


@app.command()
def help():
    """
    Show help and usage information.
    """
    console.print(Panel(
        "[bold cyan]PhantomLite - Usage Guide[/bold cyan]\n\n"
        "[yellow]Commands:[/yellow]\n"
        "  recon <domain>      Run full automated reconnaissance scan\n"
        "  subdomains <domain> Discover subdomains\n"
        "  wayback <domain>    Discover historical URLs\n"
        "  portscan <host>     Scan for open ports\n"
        "  takeover <domain>   Check for subdomain takeovers\n"
        "  cloudscan <domain>  Scan for exposed cloud buckets\n"
        "  livecheck <domains> Check which hosts are live\n"
        "  crawl <url>         Crawl a website\n"
        "  fuzz <url>          Fuzz directories\n"
        "  version             Show version\n"
        "\n[yellow]Options:[/yellow]\n"
        "  -o, --output        Output directory/file\n"
        "  -d, --depth         Crawl depth\n"
        "  -p, --pages         Max pages to crawl\n"
        "  -t, --threads       Concurrent threads\n"
        "  --fast              Fast mode\n"
        "  -v, --verbose       Verbose output\n"
        "\n[red]WARNING: Use only on authorized targets![/red]",
        border_style="cyan"
    ))


def run():
    app()


if __name__ == "__main__":
    run()
