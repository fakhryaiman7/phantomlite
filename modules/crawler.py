"""
PhantomLite Web Crawler Module
Crawls web pages to extract links, forms, and parameters.
"""
import asyncio
import re
from typing import Set, List, Dict, Optional, Any
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse
from dataclasses import dataclass
from utils.http import HTTPClient
from utils.helpers import extract_links, extract_forms, is_sensitive_path, is_sensitive_param


@dataclass
class CrawlResult:
    url: str
    links: Set[str]
    forms: List[Dict]
    inputs: List[Dict]
    parameters: Set[str]
    is_sensitive: bool
    title: Optional[str]
    status: int


class WebCrawler:
    def __init__(self, http_client: HTTPClient, logger=None):
        self.http = http_client
        self.logger = logger
        self.visited: Set[str] = set()
        self.results: List[CrawlResult] = []
        self.all_links: Set[str] = set()
        self.all_forms: List[Dict] = []
        self.all_inputs: List[Dict] = []
        self.all_params: Set[str] = set()
        self.base_domain: str = ""
    
    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        path = parsed.path or '/'
        
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc.lower(),
            path.rstrip('/'),
            parsed.params,
            parsed.query,
            ''
        ))
        
        return normalized
    
    def _should_crawl(self, url: str) -> bool:
        if url in self.visited:
            return False
        
        try:
            parsed = urlparse(url)
            if not parsed.netloc.endswith(self.base_domain) and not parsed.netloc == self.base_domain:
                return False
            
            if any(ext in url.lower() for ext in ['.pdf', '.jpg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.woff2']):
                return False
            
            return True
        except Exception:
            return False
    
    def _extract_info(self, html: str, url: str) -> tuple:
        links = extract_links(html, url)
        
        forms = extract_forms(html, url)
        
        inputs = []
        for form in forms:
            inputs.extend(form.get('inputs', []))
        
        params = set()
        for link in links:
            try:
                parsed = urlparse(link)
                query_params = parse_qs(parsed.query)
                params.update(query_params.keys())
            except Exception:
                pass
        
        for form in forms:
            for inp in form.get('inputs', []):
                if inp.get('name'):
                    params.add(inp['name'])
        
        sensitive = is_sensitive_path(urlparse(url).path)
        
        return links, forms, inputs, params, sensitive
    
    async def crawl_page(self, url: str) -> Optional[CrawlResult]:
        if not self._should_crawl(url):
            return None
        
        normalized = self._normalize_url(url)
        if normalized in self.visited:
            return None
        
        self.visited.add(normalized)
        
        try:
            resp = await self.http.get(normalized, allow_redirects=True)
            if not resp:
                return None
            
            links, forms, inputs, params, sensitive = self._extract_info(resp.body, resp.url)
            
            links = {self._normalize_url(link) for link in links if link}
            
            result = CrawlResult(
                url=resp.url,
                links=links,
                forms=forms,
                inputs=inputs,
                parameters=params,
                is_sensitive=sensitive or is_sensitive_path(urlparse(resp.url).path),
                title=resp.title,
                status=resp.status
            )
            
            self.results.append(result)
            self.all_links.update(links)
            self.all_forms.extend(forms)
            self.all_inputs.extend(inputs)
            self.all_params.update(params)
            
            return result
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Crawl error for {url}: {e}")
            return None
    
    async def crawl(
        self,
        start_url: str,
        max_depth: int = 2,
        max_pages: int = 50
    ) -> List[CrawlResult]:
        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc.lower().replace('www.', '')
        
        if self.logger:
            self.logger.scan(f"Starting crawl from {start_url} (depth: {max_depth})...")
        
        normalized_start = self._normalize_url(start_url)
        await self.crawl_page(normalized_start)
        
        current_depth = 0
        urls_to_crawl = list(self.all_links)
        depth_urls = {0: {normalized_start}}
        
        while current_depth < max_depth and len(self.visited) < max_pages:
            next_urls = set()
            
            for url in urls_to_crawl:
                if len(self.visited) >= max_pages:
                    break
                
                if self._should_crawl(url):
                    result = await self.crawl_page(url)
                    if result:
                        next_urls.update(result.links)
            
            urls_to_crawl = list(next_urls - self.visited)
            current_depth += 1
        
        if self.logger:
            self.logger.success(f"Crawl complete: {len(self.visited)} pages, {len(self.all_links)} links, {len(self.all_forms)} forms")
        
        return self.results
    
    def get_endpoints(self) -> List[Dict[str, Any]]:
        endpoints = []
        
        for result in self.results:
            path = urlparse(result.url).path
            if path and path != '/':
                endpoints.append({
                    'url': result.url,
                    'path': path,
                    'method': 'GET',
                    'params': list(result.parameters),
                    'is_sensitive': result.is_sensitive
                })
        
        for form in self.all_forms:
            endpoints.append({
                'url': form['action'],
                'path': urlparse(form['action']).path,
                'method': form['method'],
                'params': [inp['name'] for inp in form.get('inputs', []) if inp.get('name')],
                'is_sensitive': is_sensitive_path(urlparse(form['action']).path)
            })
        
        return endpoints
    
    def get_sensitive_urls(self) -> List[str]:
        return [r.url for r in self.results if r.is_sensitive]


async def crawl_site(
    start_url: str,
    logger=None,
    max_depth: int = 2,
    max_pages: int = 50
) -> List[CrawlResult]:
    async with HTTPClient(rate_limit=15, timeout=15) as http:
        crawler = WebCrawler(http, logger)
        return await crawler.crawl(start_url, max_depth, max_pages)
