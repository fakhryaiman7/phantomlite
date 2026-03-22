"""
PhantomLite Live Host Checker Module
Checks which subdomains are live using async HTTP requests.
"""
import asyncio
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
from urllib.parse import urlparse
from utils.http import HTTPClient, check_ports_batch
from utils.helpers import detect_tech_stack, calculate_hash


@dataclass
class HostInfo:
    url: str
    subdomain: str
    status: int
    response_time: float
    title: Optional[str]
    server: Optional[str]
    content_length: int
    technologies: List[str]
    is_live: bool


class LiveChecker:
    COMMON_PORTS = [80, 443, 8080, 8443, 3000, 8000, 8888, 5000]
    
    def __init__(self, http_client: HTTPClient, logger=None):
        self.http = http_client
        self.logger = logger
        self.results: List[HostInfo] = []
    
    async def check_host(self, subdomain: str, ports: List[int] = None) -> Optional[HostInfo]:
        if ports is None:
            ports = self.COMMON_PORTS
        
        http_url = f"http://{subdomain}"
        https_url = f"https://{subdomain}"
        
        host_info = None
        
        resp = await self.http.get(https_url, allow_redirects=True)
        if resp:
            host_info = HostInfo(
                url=resp.url,
                subdomain=subdomain,
                status=resp.status,
                response_time=resp.response_time,
                title=resp.title,
                server=resp.headers.get('Server'),
                content_length=len(resp.body),
                technologies=detect_tech_stack(resp.headers, resp.body),
                is_live=True
            )
        else:
            resp = await self.http.get(http_url, allow_redirects=True)
            if resp:
                host_info = HostInfo(
                    url=resp.url,
                    subdomain=subdomain,
                    status=resp.status,
                    response_time=resp.response_time,
                    title=resp.title,
                    server=resp.headers.get('Server'),
                    content_length=len(resp.body),
                    technologies=detect_tech_stack(resp.headers, resp.body),
                    is_live=True
                )
            else:
                open_ports = await self.check_ports_http(subdomain, ports)
                if open_ports:
                    scheme = 'https' if 443 in open_ports or 8443 in open_ports else 'http'
                    port_str = f":{open_ports[0]}" if open_ports[0] not in [80, 443] else ''
                    url = f"{scheme}://{subdomain}{port_str}"
                    
                    host_info = HostInfo(
                        url=url,
                        subdomain=subdomain,
                        status=0,
                        response_time=0,
                        title=None,
                        server=None,
                        content_length=0,
                        technologies=[],
                        is_live=True
                    )
        
        return host_info
    
    async def check_ports_http(self, host: str, ports: List[int]) -> List[int]:
        open_ports = []
        
        for port in ports:
            try:
                url = f"http://{host}:{port}"
                resp = await self.http.get(url, allow_redirects=False)
                if resp and resp.status < 500:
                    open_ports.append(port)
            except Exception:
                pass
            
            try:
                url = f"https://{host}:{port}"
                resp = await self.http.get(url, allow_redirects=False)
                if resp and resp.status < 500:
                    if port not in open_ports:
                        open_ports.append(port)
            except Exception:
                pass
        
        return open_ports
    
    async def check_multiple(self, subdomains: List[str], ports: List[int] = None) -> List[HostInfo]:
        if self.logger:
            self.logger.scan(f"Checking {len(subdomains)} hosts for liveness...")
        
        tasks = [self.check_host(subdomain, ports) for subdomain in subdomains]
        results = await asyncio.gather(*tasks)
        
        live_hosts = [r for r in results if r is not None]
        
        if self.logger:
            self.logger.success(f"Found {len(live_hosts)} live hosts out of {len(subdomains)} checked")
        
        self.results = live_hosts
        return live_hosts
    
    def get_live_urls(self) -> List[str]:
        return [h.url for h in self.results if h.is_live]
    
    def get_by_status(self, status: int) -> List[HostInfo]:
        return [h for h in self.results if h.status == status]
    
    def get_interesting(self) -> List[HostInfo]:
        interesting_statuses = [200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403]
        return [h for h in self.results if h.status in interesting_statuses or h.is_live]


async def check_live_hosts(subdomains: List[str], logger=None, ports: List[int] = None) -> List[HostInfo]:
    async with HTTPClient(rate_limit=20, timeout=15) as http:
        checker = LiveChecker(http, logger)
        return await checker.check_multiple(subdomains, ports)
