"""
PhantomLite Web Crawler Module (Enhanced)
Crawls web pages to extract links, forms, parameters, and JavaScript files.
"""
import asyncio
import re
from typing import Set, List, Dict, Optional, Any
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse
from dataclasses import dataclass, field
from utils.http import HTTPClient
from utils.dedup import Deduplicator, ParameterExtractor


@dataclass
class CrawlResult:
    url: str
    links: Set[str]
    forms: List[Dict]
    inputs: List[Dict]
    parameters: Set[str]
    js_files: Set[str]
    is_sensitive: bool
    title: Optional[str]
    status: int


class WebCrawler:
    SENSITIVE_PATHS = [
        'admin', 'login', 'wp-admin', 'dashboard', 'panel', 'cpanel',
        'api', 'auth', 'user', 'account', 'profile', 'settings',
        'upload', 'file', 'manage', 'config', 'setup', 'install',
        'debug', 'test', 'staging', 'dev', 'internal', 'private',
        'backup', 'database', 'sql', 'mysql', 'phpmyadmin', 'console',
        'password', 'reset', 'register', 'signup', 'checkout', 'payment'
    ]
    
    def __init__(self, http_client: HTTPClient, logger=None):
        self.http = http_client
        self.logger = logger
        self.dedup = Deduplicator()
        self.param_extractor = ParameterExtractor()
        self.visited: Set[str] = set()
        self.results: List[CrawlResult] = []
        self.all_links: Set[str] = set()
        self.all_forms: List[Dict] = []
        self.all_inputs: List[Dict] = []
        self.all_params: Set[str] = set()
        self.all_js_files: Set[str] = set()
        self.all_endpoints: List[Dict] = []
        self.base_domain: str = ""
    
    def _normalize_url(self, url: str, keep_params: bool = True) -> str:
        try:
            url = url.strip()
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urlparse(url)
            path = parsed.path or '/'
            
            if not keep_params:
                query = ''
            else:
                query = parsed.query
            
            normalized = urlunparse((
                parsed.scheme,
                parsed.netloc.lower(),
                re.sub(r'/+', '/', path),
                parsed.params,
                query,
                ''
            ))
            
            return normalized
        except Exception:
            return url
    
    def _should_crawl(self, url: str) -> bool:
        if self._normalize_url(url, False) in self.visited:
            return False
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().replace('www.', '')
            base = self.base_domain.lower().replace('www.', '')
            
            if domain != base and not domain.endswith(f'.{base}'):
                return False
            
            skip_extensions = [
                '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
                '.css', '.js', '.svg', '.woff', '.woff2', '.ttf', '.eot',
                '.mp4', '.mp3', '.wav', '.zip', '.tar', '.gz', '.rar',
                '.exe', '.dmg', '.pkg', '.deb', '.rpm'
            ]
            
            if any(url.lower().endswith(ext) for ext in skip_extensions):
                return False
            
            return True
        except Exception:
            return False
    
    def _is_sensitive_path(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            return any(kw in path for kw in self.SENSITIVE_PATHS)
        except Exception:
            return False
    
    def _extract_from_html(self, html: str, base_url: str) -> Dict[str, Any]:
        links = set()
        forms = []
        js_files = set()
        
        link_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in link_pattern.finditer(html):
            href = match.group(1)
            
            if any(href.startswith(x) for x in ['javascript:', 'mailto:', 'tel:', '#']):
                continue
            
            if href.startswith('/'):
                parsed = urlparse(base_url)
                href = f"{parsed.scheme}://{parsed.netloc}{href}"
            elif not href.startswith(('http://', 'https://')):
                parsed = urlparse(base_url)
                href = f"{parsed.scheme}://{parsed.netloc}/{href}"
            
            if href:
                links.add(href.split('#')[0].split('?')[0])
        
        forms = self.param_extractor.extract_from_forms(html)
        
        script_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\'][^>]*>', re.IGNORECASE)
        for match in script_pattern.finditer(html):
            src = match.group(1)
            if src.startswith('//'):
                src = 'https:' + src
            elif src.startswith('/'):
                parsed = urlparse(base_url)
                src = f"{parsed.scheme}://{parsed.netloc}{src}"
            elif not src.startswith(('http://', 'https://')):
                src = urljoin(base_url, src)
            js_files.add(src)
        
        return {
            'links': links,
            'forms': forms,
            'js_files': js_files
        }
    
    def _extract_params(self, html: str, url: str) -> Set[str]:
        params = set()
        
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        params.update(query_params.keys())
        
        forms = self.param_extractor.extract_from_forms(html)
        for form in forms:
            for inp in form.get('inputs', []):
                if inp.get('name'):
                    params.add(inp['name'])
        
        hidden_pattern = re.compile(r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
        for match in hidden_pattern.finditer(html):
            params.add(match.group(1))
        
        return params
    
    def _extract_endpoints(self, url: str, params: Set[str], forms: List[Dict], is_sensitive: bool) -> List[Dict]:
        endpoints = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        
        endpoints.append({
            'url': url,
            'path': path,
            'base_url': base_url,
            'method': 'GET',
            'params': list(params),
            'has_params': len(params) > 0,
            'is_sensitive': is_sensitive,
            'source': 'crawl'
        })
        
        for form in forms:
            form_action = form.get('action', '')
            if not form_action:
                form_action = url
            
            form_method = form.get('method', 'GET').upper()
            
            if form_action.startswith('/'):
                form_action = base_url + form_action
            
            form_inputs = form.get('inputs', [])
            form_params = [inp.get('name', '') for inp in form_inputs if inp.get('name')]
            
            form_sensitive = self._is_sensitive_path(form_action)
            
            endpoints.append({
                'url': form_action,
                'path': urlparse(form_action).path,
                'base_url': base_url,
                'method': form_method,
                'params': form_params,
                'has_params': len(form_params) > 0,
                'is_sensitive': form_sensitive,
                'source': 'form'
            })
        
        return endpoints
    
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
            
            extracted = self._extract_from_html(resp.body, resp.url)
            links = {self._normalize_url(l, False) for l in extracted['links'] if l}
            js_files = extracted['js_files']
            forms = extracted['forms']
            
            params = self._extract_params(resp.body, resp.url)
            
            is_sensitive = self._is_sensitive_path(resp.url)
            
            result = CrawlResult(
                url=resp.url,
                links=links,
                forms=forms,
                inputs=[inp for form in forms for inp in form.get('inputs', [])],
                parameters=params,
                js_files=js_files,
                is_sensitive=is_sensitive,
                title=resp.title,
                status=resp.status
            )
            
            self.results.append(result)
            self.all_links.update(links)
            self.all_forms.extend(forms)
            self.all_js_files.update(js_files)
            self.all_params.update(params)
            
            endpoints = self._extract_endpoints(resp.url, params, forms, is_sensitive)
            self.all_endpoints.extend(endpoints)
            
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
        self.base_domain = parsed.netloc
        
        if self.logger:
            self.logger.scan(f"Starting crawl from {start_url} (depth: {max_depth})...")
        
        normalized_start = self._normalize_url(start_url)
        await self.crawl_page(normalized_start)
        
        current_depth = 0
        urls_to_crawl = list(self.all_links)
        
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
        
        deduplicated_endpoints = self.dedup.merge_endpoints(self.all_endpoints)
        self.all_endpoints = deduplicated_endpoints
        
        if self.logger:
            self.logger.success(
                f"Crawl complete: {len(self.visited)} pages, {len(self.all_links)} links, "
                f"{len(self.all_forms)} forms, {len(self.all_params)} params, {len(self.all_js_files)} JS files"
            )
        
        return self.results
    
    def get_endpoints(self) -> List[Dict]:
        return self.all_endpoints
    
    def get_parameterized_urls(self) -> List[str]:
        urls = []
        for result in self.results:
            if result.parameters:
                urls.append(result.url)
        return urls
    
    def get_sensitive_urls(self) -> List[str]:
        return [r.url for r in self.results if r.is_sensitive]
    
    def get_js_files(self) -> List[str]:
        return list(self.all_js_files)
    
    def get_login_forms(self) -> List[Dict]:
        login_forms = []
        for form in self.all_forms:
            inputs = form.get('inputs', [])
            if self.param_extractor.is_login_form(inputs):
                login_forms.append(form)
        return login_forms
    
    def get_upload_forms(self) -> List[Dict]:
        upload_forms = []
        for form in self.all_forms:
            inputs = form.get('inputs', [])
            if self.param_extractor.is_upload_form(inputs):
                upload_forms.append(form)
        return upload_forms


async def crawl_site(
    start_url: str,
    logger=None,
    max_depth: int = 2,
    max_pages: int = 50
) -> List[CrawlResult]:
    async with HTTPClient(rate_limit=15, timeout=15) as http:
        crawler = WebCrawler(http, logger)
        return await crawler.crawl(start_url, max_depth, max_pages)
