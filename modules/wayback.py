"""
PhantomLite Wayback Machine Module
Discovers historical URLs and endpoints using the Wayback Machine API.
"""
import asyncio
import json
import re
from typing import List, Set, Dict, Optional
from urllib.parse import urlparse
from utils.http import HTTPClient
from utils.dedup import Deduplicator


class WaybackScanner:
    API_URL = "http://web.archive.org/cdx/search/xd?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    
    def __init__(self, http_client: HTTPClient = None, logger=None):
        self.http = http_client
        self.logger = logger
        self.dedup = Deduplicator()
        self.discovered_urls: Set[str] = set()
    
    async def find_urls(self, domain: str) -> List[str]:
        if self.logger:
            self.logger.scan(f"Fetching historical URLs from Wayback Machine for {domain}...")
        
        if not self.http:
            return []
        
        target_url = self.API_URL.format(domain=domain)
        
        try:
            resp = await self.http.get(target_url, timeout=30)
            if not resp or resp.status != 200:
                return []
            
            try:
                data = json.loads(resp.body)
                if not data or len(data) < 2:
                    return []
                
                # First row is header ["original"]
                urls = [row[0] for row in data[1:]]
                
                # Basic filtering
                filtered_urls = self._filter_urls(urls, domain)
                self.discovered_urls.update(filtered_urls)
                
                if self.logger:
                    self.logger.success(f"Discovered {len(filtered_urls)} historical URLs")
                
                return list(self.discovered_urls)
                
            except json.JSONDecodeError:
                return []
                
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Wayback error for {domain}: {e}")
            return []
    
    def _filter_urls(self, urls: List[str], domain: str) -> List[str]:
        filtered = []
        # Exclude common binary files to reduce noise
        excluded_exts = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.ico', '.pdf', '.zip', '.gz'}
        
        for url in urls:
            try:
                parsed = urlparse(url)
                if domain not in parsed.netloc:
                    continue
                
                path = parsed.path.lower()
                if any(path.endswith(ext) for ext in excluded_exts):
                    continue
                
                filtered.append(url)
            except Exception:
                continue
        
        return list(set(filtered))
    
    def get_interesting_urls(self) -> List[str]:
        """Filter for potentially interesting URLs (parameters, sensitive extensions)"""
        interesting = []
        sensitive_patterns = [
            r'\.php', r'\.asp', r'\.aspx', r'\.jsp', r'\.py', r'\.cgi',
            r'/api/', r'/v\d+/', r'\?.*=', r'logout', r'login', r'admin',
            r'\.env', r'\.git', r'\.sql', r'\.bak', r'\.old', r'\.log',
            r'config', r'backup', r'setup', r'install'
        ]
        
        for url in self.discovered_urls:
            if any(re.search(p, url, re.IGNORECASE) for p in sensitive_patterns):
                interesting.append(url)
        
        return interesting


async def find_wayback_urls(domain: str, logger=None) -> List[str]:
    async with HTTPClient(rate_limit=10) as http:
        scanner = WaybackScanner(http, logger)
        return await scanner.find_urls(domain)
