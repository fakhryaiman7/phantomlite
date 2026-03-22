"""
PhantomLite Subdomain Discovery Module
Uses free public sources like crt.sh and hackertarget.
"""
import asyncio
import re
from typing import Set, List, Optional
from bs4 import BeautifulSoup
from utils.http import HTTPClient
from utils.helpers import extract_domain


class SubdomainFinder:
    def __init__(self, http_client: HTTPClient, logger=None):
        self.http = http_client
        self.logger = logger
        self.results: Set[str] = set()
    
    async def find_from_crtsh(self, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        
        try:
            resp = await self.http.get(url)
            if resp and resp.status == 200:
                import json
                try:
                    data = json.loads(resp.body)
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        for subdomain in name_value.split('\n'):
                            subdomain = subdomain.strip().lower()
                            if subdomain.endswith(f'.{domain}') or subdomain == domain:
                                subdomain = subdomain.replace('*.', '')
                                if subdomain:
                                    subdomains.add(subdomain)
                except json.JSONDecodeError:
                    if self.logger:
                        self.logger.debug("Could not parse crt.sh JSON response")
        except Exception as e:
            if self.logger:
                self.logger.debug(f"crt.sh error: {e}")
        
        return subdomains
    
    async def find_from_hackertarget(self, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        
        try:
            resp = await self.http.get(url)
            if resp and resp.status == 200:
                for line in resp.body.split('\n'):
                    if line and ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain.endswith(f'.{domain}') or subdomain == domain:
                            subdomains.add(subdomain)
        except Exception as e:
            if self.logger:
                self.logger.debug(f"hackertarget error: {e}")
        
        return subdomains
    
    async def find_from_dnsdumpster(self, domain: str) -> Set[str]:
        subdomains = set()
        
        try:
            resp = await self.http.get(f"https://dnsdumpster.com/")
            if resp and resp.status == 200:
                csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', resp.body)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
                    
                    headers = {'Referer': 'https://dnsdumpster.com/'}
                    data = {'csrfmiddlewaretoken': csrf_token, 'target': domain, 'user': 'free'}
                    
                    resp2 = await self.http.post(
                        "https://dnsdumpster.com/",
                        data=data,
                        headers=headers
                    )
                    if resp2 and resp2.status == 200:
                        subdomain_pattern = re.compile(r'<td class="col-md-4">([a-zA-Z0-9\-\.]+\.' + re.escape(domain) + r')</td>')
                        for match in subdomain_pattern.finditer(resp2.body):
                            subdomains.add(match.group(1).lower())
        except Exception as e:
            if self.logger:
                self.logger.debug(f"dnsdumpster error: {e}")
        
        return subdomains
    
    async def find_from_certspotter(self, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        
        try:
            resp = await self.http.get(url)
            if resp and resp.status == 200:
                import json
                try:
                    data = json.loads(resp.body)
                    for entry in data:
                        for dns_name in entry.get('dns_names', []):
                            dns_name = dns_name.lower()
                            if dns_name.endswith(f'.{domain}') or dns_name == domain:
                                dns_name = dns_name.replace('*.', '')
                                if dns_name:
                                    subdomains.add(dns_name)
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            if self.logger:
                self.logger.debug(f"certspotter error: {e}")
        
        return subdomains
    
    async def find_from_rapiddns(self, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        
        try:
            resp = await self.http.get(url)
            if resp and resp.status == 200:
                soup = BeautifulSoup(resp.body, 'lxml')
                for a in soup.find_all('a', href=True):
                    subdomain = a.get('href', '')
                    if subdomain.startswith('http') and domain in subdomain:
                        parsed = re.search(r'://([^/]+)', subdomain)
                        if parsed:
                            subdomains.add(parsed.group(1).lower())
        except Exception as e:
            if self.logger:
                self.logger.debug(f"rapiddns error: {e}")
        
        return subdomains
    
    async def bruteforce_common(self, domain: str, wordlist: List[str]) -> Set[str]:
        subdomains = set()
        common_prefixes = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp',
                          'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm',
                          'autodiscover', 'autoconfig', 'm', 'imap', 'test',
                          'ns', 'blog', 'pop3', 'dev', 'www2', 'admin',
                          'forum', 'news', 'vpn', 'ns3', 'mail2', 'new',
                          'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
                          'static', 'docs', 'beta', 'shop', 'sql', 'secure']
        
        tasks = []
        for prefix in common_prefixes:
            subdomain = f"{prefix}.{domain}"
            tasks.append(self._check_subdomain(subdomain))
        
        results = await asyncio.gather(*tasks)
        for subdomain, is_live in results:
            if is_live:
                subdomains.add(subdomain)
        
        return subdomains
    
    async def _check_subdomain(self, subdomain: str) -> tuple:
        url = f"https://{subdomain}"
        try:
            resp = await self.http.get(url, allow_redirects=True)
            if resp and resp.status < 500:
                return (subdomain, True)
        except Exception:
            pass
        
        url = f"http://{subdomain}"
        try:
            resp = await self.http.get(url, allow_redirects=True)
            if resp and resp.status < 500:
                return (subdomain, True)
        except Exception:
            pass
        
        return (subdomain, False)
    
    async def enumerate(self, domain: str, bruteforce: bool = True) -> List[str]:
        if self.logger:
            self.logger.scan(f"Starting subdomain enumeration for {domain}...")
        
        all_subdomains = set()
        all_subdomains.add(domain)
        
        sources = [
            self.find_from_crtsh(domain),
            self.find_from_hackertarget(domain),
            self.find_from_rapiddns(domain),
        ]
        
        if bruteforce:
            wordlist = ['api', 'cdn', 'docs', 'dev', 'staging', 'test', 'admin', 'app']
            sources.append(self.find_from_certspotter(domain))
            sources.append(self.bruteforce_common(domain, wordlist))
        
        results = await asyncio.gather(*sources, return_exceptions=True)
        
        for result in results:
            if isinstance(result, set):
                all_subdomains.update(result)
        
        final_results = sorted(list(all_subdomains))
        
        if self.logger:
            self.logger.success(f"Found {len(final_results)} unique subdomains")
        
        return final_results


async def find_subdomains(domain: str, logger=None, bruteforce: bool = True) -> List[str]:
    async with HTTPClient(rate_limit=15) as http:
        finder = SubdomainFinder(http, logger)
        return await finder.enumerate(domain, bruteforce)
