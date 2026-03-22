"""
PhantomLite Pipeline Module
Orchestrates the reconnaissance workflow in the correct order.
"""
import asyncio
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
from utils.logger import get_logger
from utils.helpers import extract_domain, load_cache, save_cache
from modules.subdomain import find_subdomains
from modules.live import check_live_hosts, HostInfo
from modules.crawler import crawl_site, CrawlResult
from modules.fuzz import fuzz_directories, FuzzResult
from modules.vuln import check_vulnerabilities, VulnFinding
from core.analyzer import Analyzer, AnalysisResult
from core.scorer import Scorer, ScoredTarget


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
        
        self.subdomains: List[str] = []
        self.live_hosts: List[HostInfo] = []
        self.crawl_results: List[CrawlResult] = []
        self.fuzz_results: List[FuzzResult] = []
        self.vuln_findings: List[VulnFinding] = []
        self.analysis_results: List[AnalysisResult] = []
        self.scored_targets: List[ScoredTarget] = []
        
        self.cache_file = self.output_dir / f"{self.domain}_cache.json"
    
    async def run(self):
        self.logger.header(f"PhantomLite Recon Pipeline - {self.domain}")
        
        self.logger.warning("USE ONLY ON AUTHORIZED TARGETS")
        self.logger.info(f"Starting reconnaissance on: {self.domain}")
        
        if self.use_cache:
            self._load_from_cache()
        
        await self._step1_subdomain_discovery()
        await self._step2_live_host_check()
        await self._step3_web_crawl()
        await self._step4_directory_fuzz()
        await self._step5_vulnerability_check()
        await self._step6_analysis()
        
        self._generate_report()
        
        if self.use_cache:
            self._save_to_cache()
        
        return self._compile_results()
    
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
        
        self.logger.success(f"Discovered {len(self.subdomains)} subdomains")
    
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
            self.logger.print_table(
                "Live Hosts",
                ["URL", "Status", "Title", "Tech"],
                [[
                    h.url[:60],
                    h.status,
                    (h.title or 'N/A')[:30],
                    ', '.join(h.technologies[:2]) if h.technologies else 'N/A'
                ] for h in self.live_hosts[:20]]
            )
    
    async def _step3_web_crawl(self):
        self.logger.section("Step 3: Web Crawling")
        
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
        
        self.logger.success(f"Crawled {len(self.crawl_results)} pages")
    
    async def _step4_directory_fuzz(self):
        self.logger.section("Step 4: Directory Fuzzing")
        
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
            self.logger.print_table(
                "Interesting Fuzz Results",
                ["URL", "Status", "Length"],
                [[r.url[:60], r.status, r.content_length] for r in interesting[:15]]
            )
    
    async def _step5_vulnerability_check(self):
        self.logger.section("Step 5: Vulnerability Checks")
        
        urls_with_params = []
        
        for result in self.crawl_results:
            urls_with_params.append({
                'url': result.url,
                'params': list(result.parameters),
                'forms': result.forms
            })
        
        for host in self.live_hosts:
            urls_with_params.append({
                'url': host.url,
                'params': [],
                'forms': []
            })
        
        if urls_with_params:
            self.vuln_findings = await check_vulnerabilities(
                urls_with_params,
                logger=self.logger
            )
            
            if self.vuln_findings:
                self.logger.print_table(
                    "Vulnerability Findings",
                    ["Type", "URL", "Severity"],
                    [[f.vuln_type, f.url[:50], f.severity.upper()] for f in self.vuln_findings[:15]]
                )
    
    async def _step6_analysis(self):
        self.logger.section("Step 6: Analysis & Scoring")
        
        analyzer = Analyzer(self.logger)
        
        endpoint_results = analyzer.analyze_crawl_results(self.crawl_results)
        
        endpoints = []
        for result in self.crawl_results:
            endpoints.append({
                'url': result.url,
                'path': result.url.split('://')[-1].split('/', 1)[-1] if '/' in result.url else '/',
                'method': 'GET',
                'params': list(result.parameters),
                'is_sensitive': result.is_sensitive
            })
        
        endpoint_analysis = analyzer.analyze_endpoints(endpoints)
        
        self.analysis_results = endpoint_results + endpoint_analysis
        self.analysis_results.sort(key=lambda x: x.score, reverse=True)
        
        scorer = Scorer(self.logger)
        
        for result in self.analysis_results:
            scorer.targets.append(ScoredTarget(
                url=result.target,
                score=result.score,
                category=result.target_type,
                reasons=result.suggestions,
                metadata=result.details
            ))
        
        vuln_scored = scorer.score_vuln_findings(self.vuln_findings)
        scorer.targets.extend(vuln_scored)
        
        self.scored_targets = sorted(scorer.targets, key=lambda x: x.score, reverse=True)
        
        high_value = scorer.get_high_value_targets()
        
        if high_value:
            self.logger.section("HIGH VALUE TARGETS")
            self.logger.print_table(
                "Top Targets",
                ["Target", "Type", "Score", "Details"],
                [[
                    t.url[:50],
                    t.category,
                    t.score,
                    ', '.join(t.reasons[:2]) if t.reasons else ''
                ] for t in high_value[:10]],
                style="red"
            )
    
    def _generate_report(self):
        self.logger.section("RECON SUMMARY")
        
        summary = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'statistics': {
                'subdomains_found': len(self.subdomains),
                'live_hosts': len(self.live_hosts),
                'pages_crawled': len(self.crawl_results),
                'directories_found': len(self.fuzz_results),
                'vuln_findings': len(self.vuln_findings),
                'high_value_targets': len([t for t in self.scored_targets if t.score >= 40])
            },
            'high_value_targets': [
                {
                    'url': t.url,
                    'score': t.score,
                    'category': t.category,
                    'reasons': t.reasons
                } for t in self.scored_targets[:20]
            ],
            'vulnerability_findings': [
                {
                    'type': f.vuln_type,
                    'url': f.url,
                    'severity': f.severity,
                    'description': f.description,
                    'recommendation': f.recommendation
                } for f in self.vuln_findings
            ]
        }
        
        report_file = self.output_dir / f"{self.domain}_report.json"
        
        import json
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, default=str)
        
        self.logger.success(f"Report saved to: {report_file}")
    
    def _compile_results(self) -> Dict[str, Any]:
        return {
            'domain': self.domain,
            'subdomains': self.subdomains,
            'live_hosts': [
                {
                    'url': h.url,
                    'status': h.status,
                    'title': h.title,
                    'technologies': h.technologies
                } for h in self.live_hosts
            ],
            'crawl_results': [
                {
                    'url': r.url,
                    'title': r.title,
                    'parameters': list(r.parameters),
                    'forms': r.forms
                } for r in self.crawl_results
            ],
            'fuzz_results': [
                {
                    'url': r.url,
                    'status': r.status,
                    'is_sensitive': r.is_sensitive
                } for r in self.fuzz_results
            ],
            'vuln_findings': [
                {
                    'type': f.vuln_type,
                    'url': f.url,
                    'severity': f.severity,
                    'description': f.description
                } for f in self.vuln_findings
            ],
            'scored_targets': [
                {
                    'url': t.url,
                    'score': t.score,
                    'category': t.category,
                    'reasons': t.reasons
                } for t in self.scored_targets
            ]
        }
    
    def _save_to_cache(self):
        cache_data = {
            'subdomains': self.subdomains,
            'live_hosts': [(h.url, h.status, h.title) for h in self.live_hosts],
            'timestamp': datetime.now().isoformat()
        }
        save_cache(cache_data, self.cache_file)
    
    def _load_from_cache(self):
        if not self.cache_file.exists():
            return
        
        cache_data = load_cache(self.cache_file)
        if not cache_data:
            return
        
        try:
            cached_time = datetime.fromisoformat(cache_data.get('timestamp', ''))
            if (datetime.now() - cached_time).days < 1:
                self.logger.info("Loading results from cache...")
                self.subdomains = cache_data.get('subdomains', [])
        except Exception:
            pass


async def run_recon(
    domain: str,
    logger=None,
    **kwargs
) -> Dict[str, Any]:
    pipeline = ReconPipeline(domain, logger, **kwargs)
    return await pipeline.run()
