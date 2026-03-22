"""
PhantomLite Directory Fuzzing Module
Lightweight directory/file discovery using small wordlist.
"""
import asyncio
from typing import List, Set, Dict, Optional
from dataclasses import dataclass
from pathlib import Path
from utils.http import HTTPClient
from utils.helpers import is_sensitive_path


@dataclass
class FuzzResult:
    url: str
    status: int
    content_length: int
    redirect: Optional[str]
    is_sensitive: bool


DEFAULT_WORDLIST = [
    'admin', 'login', 'wp-admin', 'administrator', 'dashboard',
    'api', 'api-docs', 'swagger', 'graphiql', 'console',
    'wp-login.php', 'wp-admin/admin-ajax.php',
    'admin/login', 'admin/dashboard', 'admin/config',
    'administrator/index', 'admin.php', 'login.php',
    'auth', 'auth/login', 'auth/admin', 'auth/signin',
    'panel', 'cpanel', 'webmail', 'whm',
    'backup', 'backups', 'backup.sql', 'database.sql',
    'db', 'database', 'sql', 'mysql', 'phpinfo', 'info.php',
    'config', 'configuration', 'settings', '.env', '.env.bak',
    '.git/config', '.git/HEAD', '.gitignore',
    'server-status', 'status', 'health', 'ping',
    'robots.txt', 'sitemap.xml', '.well-known/security.txt',
    'test', 'testing', 'staging', 'dev', 'development',
    'demo', 'sandbox', 'beta', 'preview',
    'uploads', 'upload', 'files', 'images', 'img',
    'static', 'assets', 'css', 'js', 'javascript',
    'media', 'documents', 'docs', 'documentation',
    'about', 'contact', 'help', 'support',
    'user', 'users', 'account', 'profile', 'settings',
    'password', 'reset', 'forgot', 'recovery',
    'register', 'signup', 'join', 'signin',
    'logout', 'exit', 'signout',
    'search', 'query', 'find', 'filter',
    'comments', 'feedback', 'review',
    'terms', 'privacy', 'policy', 'legal',
    '.htaccess', '.htpasswd', 'web.config',
    'crossdomain.xml', 'clientaccesspolicy.xml',
    'favicon.ico', 'apple-touch-icon.png',
    '404', '403', '500', 'error', 'errors',
    'debug', 'trace', 'verbose',
    'internal', 'private', 'secret', 'hidden',
    'v1', 'v2', 'v3', 'version',
    'rest', 'graphql', 'soap',
    'xml', 'json', 'yaml', 'csv',
    'export', 'import', 'sync',
    'cron', 'jobs', 'tasks',
    'logs', 'log', 'audit',
    'cache', 'tmp', 'temp', 'tempalte',
    'console', 'terminal', 'shell',
    'phpunit', 'test.php', 'server.php',
    'web.config', 'application.config',
    'gateway', 'proxy', 'service',
    'monitor', 'metrics', 'stats',
    'analytics', 'tracking',
    'payment', 'checkout', 'cart', 'order',
    'subscribe', 'newsletter', 'mail',
    'forum', 'blog', 'news',
    'shop', 'store', 'product', 'products',
    'category', 'categories', 'tag', 'tags',
    'ebook', 'download', 'downloads',
    'video', 'audio', 'podcast',
    'stream', 'player', 'watch',
    'feed', 'rss', 'atom',
    'sitemap', 'sitemap.xml',
    '.well-known', 'security.txt',
]


class DirectoryFuzzer:
    def __init__(self, http_client: HTTPClient, logger=None):
        self.http = http_client
        self.logger = logger
        self.results: List[FuzzResult] = []
        self.wordlist: List[str] = DEFAULT_WORDLIST
    
    def load_wordlist(self, filepath: Path):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                self.wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            if self.logger:
                self.logger.warning(f"Could not load wordlist: {e}")
    
    async def fuzz_directory(
        self,
        base_url: str,
        wordlist: List[str] = None,
        extensions: List[str] = None
    ) -> List[FuzzResult]:
        if wordlist is None:
            wordlist = self.wordlist
        
        if extensions is None:
            extensions = ['', '.php', '.html', '.htm', '.txt', '.json', '.xml']
        
        if not base_url.endswith('/'):
            base_url += '/'
        
        if self.logger:
            self.logger.scan(f"Fuzzing directories on {base_url}...")
        
        results = []
        paths_to_fuzz = []
        
        for word in wordlist:
            for ext in extensions:
                path = f"{word}{ext}"
                paths_to_fuzz.append(path)
        
        tasks = []
        for path in paths_to_fuzz:
            url = f"{base_url}{path}"
            tasks.append(self._check_path(url))
        
        fuzz_results = await asyncio.gather(*tasks)
        
        for result in fuzz_results:
            if result and result.status in [200, 201, 204, 301, 302, 303, 307, 308, 401, 403]:
                results.append(result)
                self.results.append(result)
        
        if self.logger:
            interesting = [r for r in results if r.status in [200, 401, 403] or r.is_sensitive]
            self.logger.success(f"Fuzzing complete: {len(results)} found, {len(interesting)} interesting")
        
        return results
    
    async def _check_path(self, url: str) -> Optional[FuzzResult]:
        try:
            resp = await self.http.get(url, allow_redirects=False)
            if not resp:
                return None
            
            redirect = None
            if resp.status in [301, 302, 303, 307, 308]:
                redirect = resp.headers.get('Location', '')
            
            return FuzzResult(
                url=resp.url if hasattr(resp, 'url') else url,
                status=resp.status,
                content_length=len(resp.body),
                redirect=redirect,
                is_sensitive=is_sensitive_path(url.split('://')[-1].split('/', 1)[-1] if '/' in url else url)
            )
        except Exception:
            return None
    
    def get_interesting(self) -> List[FuzzResult]:
        return [r for r in self.results if r.status in [200, 401, 403] or r.is_sensitive]
    
    def get_by_status(self, status: int) -> List[FuzzResult]:
        return [r for r in self.results if r.status == status]


async def fuzz_directories(
    base_url: str,
    logger=None,
    wordlist: List[str] = None
) -> List[FuzzResult]:
    async with HTTPClient(rate_limit=20) as http:
        fuzzer = DirectoryFuzzer(http, logger)
        return await fuzzer.fuzz_directory(base_url, wordlist)
