"""
PhantomLite Pipeline Module (Enhanced)
Orchestrates the reconnaissance workflow with improved output.
"""
import asyncio
import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
from utils.logger import get_logger
from utils.helpers import extract_domain
from utils.dedup import Deduplicator
from modules.subdomain import find_subdomains
from modules.live import check_live_hosts, HostInfo
from modules.crawler import crawl_site, CrawlResult, WebCrawler
from modules.fuzz import fuzz_directories, FuzzResult
from modules.vuln import check_vulnerabilities, VulnFinding
from modules.javascript import JavaScriptAnalyzer
from modules.wayback import find_wayback_urls, WaybackScanner
from modules.portscan import scan_ports, PortResult
from modules.vuln_scanner import run_template_scan, TemplateScanner
from modules.takeover import run_takeover_check, TakeoverDetector
from modules.cloud import run_cloud_scan, CloudScanner
from utils.report_gen import generate_html_report
from core.analyzer import Analyzer
from core.scorer import AdvancedScorer


class ReconPipeline:
    def __init__(
        self,
        domain: str,
        logger=None,
        output_dir: str = "./results",
        max_depth: int = 2,
        max_pages: int = 50,
        rate_limit: float = 15,
        bruteforce: bool = True,
        use_cache: bool = True,
        fast: bool = False
    ):
        self.domain = extract_domain(domain) or domain
        self.logger = logger or get_logger()
        self.output_dir = Path(output_dir)
        self.max_depth = max_depth if not fast else 1
        self.max_pages = max_pages if not fast else 25
        self.rate_limit = rate_limit if not fast else 25
        self.bruteforce = bruteforce and not fast
        self.use_cache = use_cache
        self.fast = fast
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.dedup = Deduplicator()
        
        self.subdomains: List[str] = []
        self.live_hosts: List[HostInfo] = []
        self.crawl_results: List[CrawlResult] = []
        self.fuzz_results: List[FuzzResult] = []
        self.vuln_findings: List[VulnFinding] = []
        self.endpoints: List[Dict] = []
        self.js_endpoints: List[Dict] = []
        self.wayback_urls: List[str] = []
        self.open_ports: Dict[str, List[PortResult]] = {}
        self.scored_targets: List = []
        
        self.cache_file = self.output_dir / f"{self.domain}_cache.json"
    
    async def run(self):
        self._print_banner()
        
        self.logger.warning("USE ONLY ON AUTHORIZED TARGETS")
        self.logger.info(f"Starting reconnaissance on: {self.domain}")
        
        await self._step1_subdomain_discovery()
        await self._step1b_wayback_discovery()
        await self._step1c_takeover_check()
        await self._step1d_cloud_scan()
        await self._step2_live_host_check()
        await self._step2b_port_scanning()
        await self._step3_web_crawl()
        await self._step4_js_analysis()
        await self._step5_directory_fuzz()
        await self._step6_vulnerability_check()
        await self._step6b_template_scanning()
        await self._step7_analysis()
        
        self._generate_output_files()
        
        return self._compile_results()
    
    def _print_banner(self):
        self.logger.header(f"PhantomLite Recon Pipeline - {self.domain}")
    
    async def _step1_subdomain_discovery(self):
        self.logger.section("Step 1: Subdomain Discovery")
        
        if self.subdomains:
            self.logger.info(f"Using cached subdomains: {len(self.subdomains)}")
            return
        
        self.subdomains = await find_subdomains(
            self.domain,
            logger=self.logger,
            bruteforce=self.bruteforce
        )
        
        self.subdomains = self.dedup.dedup_urls(self.subdomains)
        
        self.logger.success(f"Discovered {len(self.subdomains)} unique subdomains")
    
    async def _step1b_wayback_discovery(self):
        self.logger.section("Step 1b: Wayback Machine URL Discovery")
        
        if self.wayback_urls:
            self.logger.info(f"Using cached wayback URLs: {len(self.wayback_urls)}")
            return
            
        self.wayback_urls = await find_wayback_urls(
            self.domain,
            logger=self.logger
        )
        
        if self.wayback_urls:
            self.logger.success(f"Discovered {len(self.wayback_urls)} historical URLs")
            
            # Add wayback URLs to endpoints for later analysis
            for url in self.wayback_urls[:100]: # Limit for performance
                self.endpoints.append({
                    'url': url,
                    'path': url.split('://')[-1].split('/', 1)[-1] if '/' in url else '/',
                    'method': 'GET',
                    'params': [],
                    'has_params': False,
                    'is_sensitive': False,
                    'source': 'wayback'
                })

    async def _step1c_takeover_check(self):
        self.logger.section("Step 1c: Subdomain Takeover Check")
        
        # Only check subdomains (not the root domain)
        targets = [s for s in self.subdomains if s != self.domain][:50]
        
        if targets:
            findings = await run_takeover_check(targets, logger=self.logger)
            self.vuln_findings.extend(findings)
            
            if findings:
                rows = [[f.url.split('//')[-1], f.vuln_type, f.severity.upper()] for f in findings]
                self.logger.print_table("Takeover Findings", ["Domain", "Type", "Severity"], rows, "red")

    async def _step1d_cloud_scan(self):
        self.logger.section("Step 1d: Cloud Storage Bucket Scanning")
        
        findings = await run_cloud_scan(self.domain, logger=self.logger)
        self.vuln_findings.extend(findings)
        
        if findings:
            rows = [[f.url, f.vuln_type, f.severity.upper()] for f in findings]
            self.logger.print_table("Cloud Findings", ["Bucket URL", "Type", "Severity"], rows, "red")
    
    async def _step2_live_host_check(self):
        self.logger.section("Step 2: Live Host Check")
        
        if self.live_hosts:
            self.logger.info(f"Using cached live hosts: {len(self.live_hosts)}")
            return
        
        self.live_hosts = await check_live_hosts(
            self.subdomains,
            logger=self.logger
        )
        
        if self.live_hosts:
            rows = []
            for h in self.live_hosts[:20]:
                title = (h.title or 'N/A')[:30]
                tech = ', '.join(h.technologies[:2]) if h.technologies else 'N/A'
                rows.append([h.url[:60], h.status, title, tech])
            
            self.logger.print_table(
                "Live Hosts",
                ["URL", "Status", "Title", "Tech"],
                rows
            )
            
    async def _step2b_port_scanning(self):
        self.logger.section("Step 2b: Port Scanning")
        
        if self.fast:
            self.logger.info("Fast mode enabled, skipping port scan")
            return
            
        # Scan top 3 live hosts to save time
        targets = [h.url.split('://')[-1].split('/')[0] for h in self.live_hosts[:3]]
        
        for host in targets:
            try:
                results = await scan_ports(host, logger=self.logger)
                if results:
                    self.open_ports[host] = results
                    
                    rows = [[r.port, r.service, r.state, r.banner[:30]] for r in results]
                    self.logger.print_table(
                        f"Open Ports - {host}",
                        ["Port", "Service", "State", "Banner"],
                        rows
                    )
            except Exception as e:
                self.logger.debug(f"Port scan failed for {host}: {e}")
    
    async def _step3_web_crawl(self):
        self.logger.section("Step 3: Web Crawling & Parameter Extraction")
        
        if self.crawl_results:
            self.logger.info(f"Using cached crawl results: {len(self.crawl_results)}")
            return
        
        urls_to_crawl = [h.url for h in self.live_hosts[:10]]
        
        for url in urls_to_crawl:
            try:
                results = await crawl_site(
                    url,
                    logger=self.logger,
                    max_depth=self.max_depth,
                    max_pages=self.max_pages
                )
                self.crawl_results.extend(results)
            except Exception as e:
                self.logger.debug(f"Crawl failed for {url}: {e}")
        
        for result in self.crawl_results:
            if hasattr(result, 'parameters') and result.parameters:
                self.endpoints.append({
                    'url': result.url,
                    'path': result.url.split('://')[-1].split('/', 1)[-1] if '/' in result.url else '/',
                    'base_url': result.url.split('://')[0] + '://' + result.url.split('://')[1].split('/')[0],
                    'method': 'GET',
                    'params': list(result.parameters),
                    'has_params': len(result.parameters) > 0,
                    'is_sensitive': result.is_sensitive,
                    'source': 'crawl'
                })
            
            for form in result.forms:
                form_action = form.get('action', '')
                if form_action:
                    self.endpoints.append({
                        'url': form_action,
                        'path': form_action.split('://')[-1].split('/', 1)[-1] if '://' in form_action else form_action,
                        'base_url': form_action.split('://')[0] + '://' + form_action.split('://')[1].split('/')[0] if '://' in form_action else '',
                        'method': form.get('method', 'GET').upper(),
                        'params': [inp.get('name', '') for inp in form.get('inputs', []) if inp.get('name')],
                        'has_params': len([inp for inp in form.get('inputs', []) if inp.get('name')]) > 0,
                        'is_sensitive': False,
                        'source': 'form'
                    })
        
        self.endpoints = self.dedup.merge_endpoints(self.endpoints)
        
        self.logger.success(f"Crawled {len(self.crawl_results)} pages, found {len(self.endpoints)} endpoints")
    
    async def _step4_js_analysis(self):
        self.logger.section("Step 4: JavaScript Analysis")
        
        js_files = []
        for result in self.crawl_results:
            js_files.extend(result.js_files)
        
        js_files = list(set(js_files))
        
        if not js_files:
            self.logger.info("No JavaScript files found")
            return
        
        self.logger.scan(f"Analyzing {len(js_files)} JavaScript files...")
        
        from utils.http import HTTPClient
        async with HTTPClient(rate_limit=self.rate_limit) as http:
            analyzer = JavaScriptAnalyzer(http, self.logger)
            
            for js_url in js_files[:30]:
                await analyzer.analyze_js_file(js_url)
            
            self.js_endpoints = analyzer.get_api_endpoints()
        
        if self.js_endpoints:
            self.logger.success(f"Found {len(self.js_endpoints)} endpoints in JavaScript")
            
            rows = []
            for ep in self.js_endpoints[:15]:
                path = ep.get('path', '')[:50]
                method = ep.get('method', 'GET')
                rows.append([path, method])
            
            self.logger.print_table(
                "JavaScript Endpoints",
                ["Endpoint", "Method"],
                rows
            )
        else:
            self.logger.info("No endpoints found in JavaScript")
    
    async def _step5_directory_fuzz(self):
        self.logger.section("Step 5: Directory Fuzzing")
        
        if self.fuzz_results:
            self.logger.info(f"Using cached fuzz results: {len(self.fuzz_results)}")
            return
        
        urls_to_fuzz = [h.url for h in self.live_hosts[:5]]
        
        for url in urls_to_fuzz:
            try:
                results = await fuzz_directories(
                    url,
                    logger=self.logger
                )
                self.fuzz_results.extend(results)
            except Exception as e:
                self.logger.debug(f"Fuzz failed for {url}: {e}")
        
        interesting = [r for r in self.fuzz_results if r.status in [200, 401, 403] or r.is_sensitive]
        if interesting:
            rows = []
            for r in interesting[:20]:
                rows.append([r.url[:60], r.status, r.content_length])
            
            self.logger.print_table(
                "Interesting Fuzz Results",
                ["URL", "Status", "Length"],
                rows
            )
    
    async def _step6_vulnerability_check(self):
        self.logger.section("Step 6: Vulnerability Checks")
        
        urls_with_params = []
        seen = set()
        
        for endpoint in self.endpoints:
            url = endpoint.get('url', '')
            if url and url not in seen:
                seen.add(url)
                urls_with_params.append({
                    'url': url,
                    'params': endpoint.get('params', []),
                    'forms': []
                })
        
        for result in self.crawl_results:
            if result.url not in seen:
                seen.add(result.url)
                urls_with_params.append({
                    'url': result.url,
                    'params': list(result.parameters),
                    'forms': result.forms
                })
        
        if urls_with_params:
            self.vuln_findings = await check_vulnerabilities(
                urls_with_params,
                logger=self.logger
            )
            
            if self.vuln_findings:
                self.logger.section("VULNERABILITIES FOUND")
                
                high = [f for f in self.vuln_findings if f.severity == 'high']
                medium = [f for f in self.vuln_findings if f.severity == 'medium']
                low = [f for f in self.vuln_findings if f.severity == 'low']
                
                if high:
                    rows = [[f.vuln_type, f.url[:50], f.severity.upper(), f.parameter] for f in high[:10]]
                    self.logger.print_table("HIGH Severity", ["Type", "URL", "Sev", "Param"], rows, "red")
                
                if medium:
                    rows = [[f.vuln_type, f.url[:50], f.severity.upper(), f.parameter] for f in medium[:10]]
                    self.logger.print_table("MEDIUM Severity", ["Type", "URL", "Sev", "Param"], rows, "yellow")
                    
    async def _step6b_template_scanning(self):
        self.logger.section("Step 6b: Template-based Vulnerability Scanning")
        
        target_urls = [h.url for h in self.live_hosts[:5]]
        
        if target_urls:
            findings = await run_template_scan(target_urls, logger=self.logger)
            self.vuln_findings.extend(findings)
            
            if findings:
                rows = [[f.vuln_type[:30], f.url[:50], f.severity.upper()] for f in findings]
                self.logger.print_table("Template Findings", ["Type", "URL", "Severity"], rows, "cyan")
    
    async def _step7_analysis(self):
        self.logger.section("Step 7: Analysis & Prioritization")
        
        all_endpoints = list(self.endpoints)
        all_endpoints.extend(self.js_endpoints)
        
        forms = []
        for result in self.crawl_results:
            forms.extend(result.forms)
        
        analyzer = Analyzer(self.logger)
        analysis_results = analyzer.analyze(
            endpoints=all_endpoints,
            forms=forms,
            vuln_findings=self.vuln_findings
        )
        
        scorer = AdvancedScorer(self.logger)
        scorer.add_from_endpoints(all_endpoints)
        scorer.add_from_forms(forms)
        scorer.add_from_findings(self.vuln_findings)
        
        self.scored_targets = scorer.get_all()
        
        high_value = scorer.get_high_value(threshold=40)
        
        if high_value:
            self.logger.section("ATTACK SURFACE - HIGH VALUE TARGETS")
            
            critical = [t for t in high_value if t.priority == 'critical']
            high = [t for t in high_value if t.priority == 'high']
            medium = [t for t in high_value if t.priority == 'medium']
            
            if critical:
                rows = [[t.url[:50], t.category, t.score, ', '.join(t.reasons[:2])] for t in critical[:10]]
                self.logger.print_table("CRITICAL", ["Target", "Type", "Score", "Reasons"], rows, "red")
            
            if high:
                rows = [[t.url[:50], t.category, t.score, ', '.join(t.reasons[:2])] for t in high[:10]]
                self.logger.print_table("HIGH", ["Target", "Type", "Score", "Reasons"], rows, "yellow")
        
        self._print_suggestions(analysis_results)
        
        summary = scorer.generate_summary()
        self._print_summary(summary)
    
    def _print_suggestions(self, analysis_results):
        self.logger.section("SUGGESTIONS")
        
        suggestions = {
            'IDOR': [],
            'XSS': [],
            'SQLi': [],
            'Open Redirect': [],
            'SSRF': [],
            'LFI': [],
            'File Upload': [],
            'API': [],
            'Other': []
        }
        
        for result in analysis_results:
            target_type = result.target_type.lower()
            
            if 'idor' in target_type:
                suggestions['IDOR'].extend(result.suggestions)
            elif 'xss' in target_type:
                suggestions['XSS'].extend(result.suggestions)
            elif 'sql' in target_type:
                suggestions['SQLi'].extend(result.suggestions)
            elif 'redirect' in target_type:
                suggestions['Open Redirect'].extend(result.suggestions)
            elif 'ssrf' in target_type:
                suggestions['SSRF'].extend(result.suggestions)
            elif 'lfi' in target_type or 'file' in target_type:
                suggestions['LFI'].extend(result.suggestions)
            elif 'upload' in target_type:
                suggestions['File Upload'].extend(result.suggestions)
            elif 'api' in target_type:
                suggestions['API'].extend(result.suggestions)
            else:
                suggestions['Other'].extend(result.suggestions)
        
        for category, items in suggestions.items():
            if items:
                unique_items = list(set(items))[:5]
                self.logger.info(f"[{category}]")
                for item in unique_items:
                    self.logger.scan(item)
    
    def _print_summary(self, summary):
        self.logger.section("RECON SUMMARY")
        
        stats = summary.get('by_priority', {})
        
        self.logger.info(f"[+] Total Targets: {summary.get('total_targets', 0)}")
        self.logger.info(f"[red]![/red] Critical: {stats.get('critical', 0)}")
        self.logger.info(f"[yellow]![/yellow] High: {stats.get('high', 0)}")
        self.logger.info(f"[blue]i[/blue] Medium: {stats.get('medium', 0)}")
        self.logger.info(f"    Low: {stats.get('low', 0)}")
    
    def _generate_output_files(self):
        base_name = self.domain.replace('.', '_')
        
        subdomains_file = self.output_dir / f"{base_name}_subdomains.txt"
        with open(subdomains_file, 'w') as f:
            f.write('\n'.join(sorted(self.subdomains)))
        self.logger.success(f"Subdomains saved to: {subdomains_file}")
        
        live_file = self.output_dir / f"{base_name}_live.txt"
        with open(live_file, 'w') as f:
            for h in self.live_hosts:
                f.write(f"{h.url}\n")
        self.logger.success(f"Live hosts saved to: {live_file}")
        
        endpoints_file = self.output_dir / f"{base_name}_endpoints.txt"
        with open(endpoints_file, 'w') as f:
            for ep in self.endpoints:
                params = ','.join(ep.get('params', []))
                f.write(f"{ep.get('url', '')} | {ep.get('method', 'GET')} | params: {params}\n")
        self.logger.success(f"Endpoints saved to: {endpoints_file}")
        
        if self.js_endpoints:
            js_endpoints_file = self.output_dir / f"{base_name}_js_endpoints.txt"
            with open(js_endpoints_file, 'w') as f:
                for ep in self.js_endpoints:
                    f.write(f"{ep.get('path', '')} | {ep.get('method', 'GET')}\n")
            self.logger.success(f"JS endpoints saved to: {js_endpoints_file}")
        
        vulns_file = self.output_dir / f"{base_name}_vulns.json"
        vulns_data = []
        for f in self.vuln_findings:
            vulns_data.append({
                'type': f.vuln_type,
                'url': f.url,
                'severity': f.severity,
                'description': f.description,
                'evidence': f.evidence,
                'recommendation': f.recommendation,
                'parameter': f.parameter
            })
        with open(vulns_file, 'w') as f:
            json.dump(vulns_data, f, indent=2)
        self.logger.success(f"Vulnerabilities saved to: {vulns_file}")
        
        report_file = self.output_dir / f"{base_name}_report.json"
        report_data = self._compile_results()
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        self.logger.success(f"Full report saved to: {report_file}")
        
        if self.open_ports:
            ports_file = self.output_dir / f"{base_name}_ports.txt"
            with open(ports_file, 'w') as f:
                for host, ports in self.open_ports.items():
                    f.write(f"Host: {host}\n")
                    for p in ports:
                        f.write(f"  - {p.port}/{p.service} ({p.state}) {p.banner}\n")
            self.logger.success(f"Open ports saved to: {ports_file}")
            
        if self.wayback_urls:
            wayback_file = self.output_dir / f"{base_name}_wayback.txt"
            with open(wayback_file, 'w') as f:
                f.write('\n'.join(self.wayback_urls))
            self.logger.success(f"Wayback URLs saved to: {wayback_file}")
            
        # Generate Interactive HTML Report
        html_file = self.output_dir / f"{base_name}_report.html"
        try:
            generate_html_report(report_data, str(html_file))
            self.logger.success(f"Interactive HTML report generated: {html_file}")
        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {e}")
    
    def _compile_results(self) -> Dict[str, Any]:
        return {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'subdomains': self.subdomains,
            'wayback_urls': self.wayback_urls,
            'open_ports': {
                host: [
                    {
                        'port': p.port,
                        'service': p.service,
                        'state': p.state,
                        'banner': p.banner
                    } for p in ports
                ] for host, ports in self.open_ports.items()
            },
            'live_hosts': [
                {
                    'url': h.url,
                    'status': h.status,
                    'title': h.title,
                    'technologies': h.technologies
                } for h in self.live_hosts
            ],
            'endpoints': [
                {
                    'url': ep.get('url', ''),
                    'method': ep.get('method', 'GET'),
                    'params': ep.get('params', []),
                    'has_params': ep.get('has_params', False),
                    'is_sensitive': ep.get('is_sensitive', False),
                    'sources': ep.get('sources', [])
                } for ep in self.endpoints
            ],
            'js_endpoints': self.js_endpoints,
            'vuln_findings': [
                {
                    'type': f.vuln_type,
                    'url': f.url,
                    'severity': f.severity,
                    'description': f.description,
                    'parameter': f.parameter
                } for f in self.vuln_findings
            ],
            'scored_targets': [
                {
                    'url': t.url,
                    'score': t.score,
                    'category': t.category,
                    'priority': t.priority,
                    'reasons': t.reasons
                } for t in self.scored_targets
            ]
        }


async def run_recon(
    domain: str,
    logger=None,
    **kwargs
) -> Dict[str, Any]:
    pipeline = ReconPipeline(domain, logger, **kwargs)
    return await pipeline.run()
