"""
PhantomLite HTTP Module
Provides async HTTP client with rate limiting and safety features.
"""
import asyncio
import aiohttp
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import ssl
import time


@dataclass
class Response:
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    response_time: float
    content_type: str
    title: Optional[str] = None


class RateLimiter:
    def __init__(self, requests_per_second: float = 10):
        self.delay = 1.0 / requests_per_second
        self.last_request = 0
    
    async def acquire(self):
        now = time.time()
        elapsed = now - self.last_request
        if elapsed < self.delay:
            await asyncio.sleep(self.delay - elapsed)
        self.last_request = time.time()


class HTTPClient:
    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 2,
        rate_limit: float = 10,
        user_agent: str = None
    ):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.rate_limiter = RateLimiter(rate_limit)
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        self.session: Optional[aiohttp.ClientSession] = None
        self._connector = None
    
    async def __aenter__(self):
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def start(self):
        if not self.session:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            self._connector = aiohttp.TCPConnector(
                limit=50,
                limit_per_host=20,
                ssl=ssl_context,
                enable_cleanup_closed=True
            )
            self.session = aiohttp.ClientSession(
                timeout=self.timeout,
                connector=self._connector,
                headers={"User-Agent": self.user_agent}
            )
    
    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None
        if self._connector:
            await self._connector.close()
            self._connector = None
    
    async def get(
        self,
        url: str,
        allow_redirects: bool = True,
        headers: Dict = None
    ) -> Optional[Response]:
        if not self.session:
            await self.start()
        
        await self.rate_limiter.acquire()
        
        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                async with self.session.get(
                    url,
                    allow_redirects=allow_redirects,
                    headers=headers,
                    ssl=False
                ) as resp:
                    body = await resp.text(errors='ignore')
                    response_time = time.time() - start_time
                    
                    title = None
                    if 'text/html' in resp.headers.get('Content-Type', ''):
                        title = self._extract_title(body)
                    
                    return Response(
                        url=str(resp.url),
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        response_time=response_time,
                        content_type=resp.headers.get('Content-Type', ''),
                        title=title
                    )
            except asyncio.TimeoutError:
                if attempt == self.max_retries - 1:
                    return None
            except aiohttp.ClientError:
                if attempt == self.max_retries - 1:
                    return None
            except Exception:
                return None
        
        return None
    
    async def post(
        self,
        url: str,
        data: Dict = None,
        json_data: Dict = None,
        headers: Dict = None
    ) -> Optional[Response]:
        if not self.session:
            await self.start()
        
        await self.rate_limiter.acquire()
        
        try:
            start_time = time.time()
            async with self.session.post(
                url,
                data=data,
                json=json_data,
                headers=headers,
                ssl=False
            ) as resp:
                body = await resp.text(errors='ignore')
                response_time = time.time() - start_time
                
                return Response(
                    url=str(resp.url),
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=body,
                    response_time=response_time,
                    content_type=resp.headers.get('Content-Type', '')
                )
        except Exception:
            return None
    
    async def head(
        self,
        url: str,
        headers: Dict = None
    ) -> Optional[Response]:
        if not self.session:
            await self.start()
        
        await self.rate_limiter.acquire()
        
        try:
            start_time = time.time()
            async with self.session.head(
                url,
                headers=headers,
                ssl=False,
                allow_redirects=False
            ) as resp:
                response_time = time.time() - start_time
                
                return Response(
                    url=str(resp.url),
                    status=resp.status,
                    headers=dict(resp.headers),
                    body="",
                    response_time=response_time,
                    content_type=resp.headers.get('Content-Type', '')
                )
        except Exception:
            return None
    
    def _extract_title(self, html: str) -> Optional[str]:
        try:
            import re
            match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            if match:
                return match.group(1).strip()[:100]
        except Exception:
            pass
        return None
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme in ('http', 'https'), result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def normalize_url(url: str) -> str:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    @staticmethod
    def get_base_url(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"


async def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def check_ports_batch(host: str, ports: List[int], timeout: float = 3.0) -> List[int]:
    tasks = [check_port(host, port, timeout) for port in ports]
    results = await asyncio.gather(*tasks)
    return [port for port, is_open in zip(ports, results) if is_open]
