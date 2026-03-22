"""
PhantomLite JavaScript Analyzer
Detects and parses JavaScript files to extract API endpoints, URLs, and hidden paths.
"""
import re
from typing import Set, List, Dict, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
from utils.http import HTTPClient
from utils.dedup import Deduplicator


@dataclass
class JSEndpoint:
    endpoint: str
    method: str
    source_file: str
    context: str


class JavaScriptAnalyzer:
    API_PATTERNS = [
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/v\d+/[^"\']+)["\']',
        r'["\'](/graphql)["\']',
        r'["\'](/rest/[^"\']+)["\']',
        r'["\'](\/api\/v\d+[^"\']+)["\']',
        r'baseURL\s*[=:]\s*["\']([^"\']+)["\']',
        r'endpoint\s*[=:]\s*["\']([^"\']+)["\']',
        r'url\s*[=:]\s*["\']([^"\']*api[^"\']*)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(\s*["\']([^"\']+)["\']',
        r'XMLHttpRequest.*["\']([^"\']+)["\']',
        r'\.get\s*\(\s*["\']([^"\']+)["\']',
        r'\.post\s*\(\s*["\']([^"\']+)["\']',
        r'\.put\s*\(\s*["\']([^"\']+)["\']',
        r'\.delete\s*\(\s*["\']([^"\']+)["\']',
        r'\.patch\s*\(\s*["\']([^"\']+)["\']',
    ]
    
    URL_PATTERNS = [
        r'["\'](https?://[^"\']+)["\']',
        r'href\s*=\s*["\']([^"\']+)["\']',
        r'src\s*=\s*["\']([^"\']+\.js[^"\']*)["\']',
        r'location\s*=\s*["\']([^"\']+)["\']',
        r'window\.location\s*=\s*["\']([^"\']+)["\']',
        r'redirect\s*\(\s*["\']([^"\']+)["\']',
    ]
    
    SECRET_PATTERNS = [
        r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\'][^"\']+["\']',
        r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']+["\']',
        r'(?:token|auth[_-]?token|access[_-]?token)\s*[=:]\s*["\'][^"\']+["\']',
        r'(?:secret|private[_-]?key)\s*[=:]\s*["\'][^"\']+["\']',
        r'bearer\s+[a-zA-Z0-9\-._~+/]+',
        r'basic\s+[a-zA-Z0-9\-._~+/]+=*',
    ]
    
    HIDDEN_PATTERNS = [
        r'\.(?:config|configure)\s*[=:]\s*\{[^}]*\}',
        r'(?:admin|dashboard|manager|control)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?:debug|verbose|trace)\s*[=:]\s*(?:true|false|1|0)',
        r'(?:internal|private|hidden)\s*[=:]\s*["\']([^"\']+)["\']',
    ]
    
    SENSITIVE_KEYWORDS = [
        'admin', 'login', 'auth', 'api', 'upload', 'file', 'user',
        'password', 'token', 'secret', 'key', 'payment', 'admin',
        'dashboard', 'manage', 'config', 'setup', 'install', 'debug',
        'internal', 'private', 'hidden', 'backup', 'database', 'sql'
    ]
    
    def __init__(self, http_client: HTTPClient = None, logger=None):
        self.http = http_client
        self.logger = logger
        self.dedup = Deduplicator()
        self.endpoints: Set[str] = set()
        self.urls: Set[str] = set()
        self.secrets: Set[str] = set()
        self.hidden_paths: Set[str] = set()
        self.js_files: Set[str] = set()
    
    def extract_from_html(self, html: str, base_url: str) -> Set[str]:
        js_files = set()
        
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
        
        return js_files
    
    async def analyze_js_file(self, js_url: str) -> Dict[str, Set]:
        results = {
            'endpoints': set(),
            'urls': set(),
            'secrets': set(),
            'hidden_paths': set()
        }
        
        if not self.http:
            return results
        
        try:
            resp = await self.http.get(js_url, timeout=10)
            if not resp or resp.status != 200:
                return results
            
            content = resp.body
            
            for pattern in self.API_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    endpoint = match.group(1)
                    if endpoint.startswith('/') or endpoint.startswith('http'):
                        results['endpoints'].add(endpoint)
            
            method_map = {
                'fetch': 'POST',
                'axios.get': 'GET',
                'axios.post': 'POST',
                'axios.put': 'PUT',
                'axios.delete': 'DELETE',
                '.get(': 'GET',
                '.post(': 'POST',
                '.put(': 'PUT',
                '.delete(': 'DELETE',
                '.patch(': 'PATCH',
            }
            
            for pattern, method in [
                (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'POST'),
                (r'axios\.[a-z]+\(\s*["\']([^"\']+)["\']', 'POST'),
            ]:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    endpoint = match.group(1)
                    results['endpoints'].add(endpoint)
            
            for pattern in self.URL_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    url = match.group(1)
                    if url.startswith('http'):
                        results['urls'].add(url)
            
            for pattern in self.SECRET_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    secret = match.group(0)
                    if len(secret) < 200:
                        results['secrets'].add(secret[:100])
            
            for pattern in self.HIDDEN_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    hidden = match.group(0)[:100]
                    results['hidden_paths'].add(hidden)
            
            self.endpoints.update(results['endpoints'])
            self.urls.update(results['urls'])
            self.secrets.update(results['secrets'])
            self.hidden_paths.update(results['hidden_paths'])
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"JS analysis error for {js_url}: {e}")
        
        return results
    
    async def analyze_js_urls(self, js_urls: List[str]) -> Dict[str, Set]:
        if not js_urls:
            return {
                'endpoints': set(),
                'urls': set(),
                'secrets': set(),
                'hidden_paths': set()
            }
        
        if self.logger:
            self.logger.scan(f"Analyzing {len(js_urls)} JavaScript files...")
        
        tasks = [self.analyze_js_file(url) for url in js_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        aggregated = {
            'endpoints': set(),
            'urls': set(),
            'secrets': set(),
            'hidden_paths': set()
        }
        
        for result in results:
            if isinstance(result, dict):
                aggregated['endpoints'].update(result['endpoints'])
                aggregated['urls'].update(result['urls'])
                aggregated['secrets'].update(result['secrets'])
                aggregated['hidden_paths'].update(result['hidden_paths'])
        
        if self.logger:
            self.logger.success(f"JS Analysis: {len(aggregated['endpoints'])} endpoints, {len(aggregated['urls'])} URLs found")
        
        return aggregated
    
    def get_api_endpoints(self) -> List[Dict]:
        endpoints = []
        for endpoint in self.endpoints:
            method = 'GET'
            if any(x in endpoint.lower() for x in ['post', 'create', 'add', 'register']):
                method = 'POST'
            elif any(x in endpoint.lower() for x in ['update', 'edit', 'modify']):
                method = 'PUT'
            elif any(x in endpoint.lower() for x in ['delete', 'remove']):
                method = 'DELETE'
            
            is_sensitive = any(kw in endpoint.lower() for kw in self.SENSITIVE_KEYWORDS)
            
            endpoints.append({
                'path': endpoint,
                'method': method,
                'is_sensitive': is_sensitive,
                'source': 'javascript'
            })
        
        return endpoints
    
    def get_discovered_urls(self) -> List[str]:
        return list(self.urls)
    
    def get_secrets(self) -> List[str]:
        return list(self.secrets)


import asyncio
