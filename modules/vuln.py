"""
PhantomLite Vulnerability Checker Module
Performs basic vulnerability checks without exploitation.
"""
import asyncio
import re
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlunparse
from utils.http import HTTPClient
from utils.helpers import is_sensitive_param, is_sensitive_path


@dataclass
class VulnFinding:
    vuln_type: str
    url: str
    severity: str
    description: str
    evidence: str
    recommendation: str


class VulnChecker:
    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '{{constructor.constructor("alert(1)")()}}'
    ]
    
    OPEN_REDIRECT_PAYLOADS = [
        'https://evil.com',
        '//evil.com',
        '///evil.com',
        'https://google.com',
        'javascript:alert(1)',
        '\/\/evil.com',
        '%2F%2Fevil.com'
    ]
    
    SECURITY_HEADERS = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'Referrer-Policy',
        'Permissions-Policy'
    ]
    
    def __init__(self, http_client: HTTPClient, logger=None):
        self.http = http_client
        self.logger = logger
        self.results: List[VulnFinding] = []
    
    async def check_reflected_xss(self, url: str, params: List[str]) -> List[VulnFinding]:
        findings = []
        
        if not params:
            return findings
        
        test_param = params[0]
        test_value = '<script>alert("XSS")</script>'
        
        for param in params:
            test_url = self._inject_param(url, param, test_value)
            
            try:
                resp = await self.http.get(test_url, allow_redirects=False)
                if resp and test_value in resp.body:
                    findings.append(VulnFinding(
                        vuln_type="Reflected XSS",
                        url=url,
                        severity="medium",
                        description=f"Parameter '{param}' reflects user input without sanitization",
                        evidence=f"Payload reflected: {test_value[:50]}...",
                        recommendation=f"Sanitize and encode user input in parameter '{param}' before reflecting"
                    ))
            except Exception:
                pass
        
        return findings
    
    async def check_open_redirect(self, url: str, params: List[str]) -> List[VulnFinding]:
        findings = []
        
        redirect_params = ['redirect', 'url', 'next', 'return', 'callback', 'continue', 'destination']
        
        for param in redirect_params:
            if param not in params:
                continue
            
            for payload in self.OPEN_REDIRECT_PAYLOADS[:3]:
                test_url = self._inject_param(url, param, payload)
                
                try:
                    resp = await self.http.get(test_url, allow_redirects=False)
                    if resp:
                        location = resp.headers.get('Location', '')
                        if payload in location or 'evil.com' in location or 'google.com' in location:
                            findings.append(VulnFinding(
                                vuln_type="Open Redirect",
                                url=url,
                                severity="medium",
                                description=f"Parameter '{param}' allows arbitrary URL redirection",
                                evidence=f"Redirects to: {location[:100]}",
                                recommendation=f"Validate and whitelist allowed redirect destinations for parameter '{param}'"
                            ))
                except Exception:
                    pass
        
        return findings
    
    async def check_missing_headers(self, url: str) -> List[VulnFinding]:
        findings = []
        
        try:
            resp = await self.http.get(url)
            if not resp:
                return findings
            
            missing_headers = []
            
            for header in self.SECURITY_HEADERS:
                if header not in resp.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                severity = "low" if len(missing_headers) < 3 else "medium"
                findings.append(VulnFinding(
                    vuln_type="Missing Security Headers",
                    url=url,
                    severity=severity,
                    description=f"Response is missing {len(missing_headers)} security headers",
                    evidence=f"Missing: {', '.join(missing_headers[:5])}",
                    recommendation="Implement recommended security headers: X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Content-Security-Policy"
                ))
        
        except Exception:
            pass
        
        return findings
    
    async def check_csrf_tokens(self, url: str, forms: List[Dict]) -> List[VulnFinding]:
        findings = []
        
        csrf_keywords = ['csrf', 'token', '_token', 'csrf_token', 'xsrf']
        
        for form in forms:
            inputs = form.get('inputs', [])
            input_names = [inp.get('name', '').lower() for inp in inputs]
            
            has_csrf = any(keyword in name for keyword in csrf_keywords for name in input_names)
            
            if not has_csrf and len(inputs) > 0:
                findings.append(VulnFinding(
                    vuln_type="Potential CSRF",
                    url=form.get('action', url),
                    severity="low",
                    description=f"Form does not appear to have CSRF protection",
                    evidence=f"Form has {len(inputs)} inputs but no CSRF token detected",
                    recommendation="Add CSRF tokens to forms that perform state-changing operations"
                ))
        
        return findings
    
    async def check_sqli_indicators(self, url: str, params: List[str]) -> List[VulnFinding]:
        findings = []
        
        sqli_indicators = ["'", '"', ' OR 1=1', '--', ';--', 'UNION SELECT']
        
        for param in params[:3]:
            for indicator in sqli_indicators[:2]:
                test_url = self._inject_param(url, param, indicator)
                
                try:
                    resp = await self.http.get(test_url, allow_redirects=False)
                    if resp:
                        body_lower = resp.body.lower()
                        
                        error_keywords = [
                            'sql', 'syntax', 'mysql', 'postgresql', 'oracle',
                            'microsoft sql', 'sqlite', 'mariadb', 'error',
                            'warning', 'exception', 'fatal'
                        ]
                        
                        errors_found = [kw for kw in error_keywords if kw in body_lower]
                        
                        if errors_found and resp.status >= 400:
                            findings.append(VulnFinding(
                                vuln_type="SQL Injection Indicator",
                                url=url,
                                severity="high",
                                description=f"Parameter '{param}' may be vulnerable to SQL injection",
                                evidence=f"SQL-related errors detected: {', '.join(errors_found[:3])}",
                                recommendation=f"Use parameterized queries and proper input validation for parameter '{param}'"
                            ))
                except Exception:
                    pass
        
        return findings
    
    async def check_all(
        self,
        urls_with_params: List[Dict]
    ) -> List[VulnFinding]:
        if self.logger:
            self.logger.scan("Starting vulnerability checks...")
        
        all_findings = []
        
        for item in urls_with_params:
            url = item.get('url')
            params = item.get('params', [])
            forms = item.get('forms', [])
            
            tasks = [
                self.check_reflected_xss(url, params),
                self.check_open_redirect(url, params),
                self.check_missing_headers(url),
                self.check_csrf_tokens(url, forms),
                self.check_sqli_indicators(url, params)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    all_findings.extend(result)
        
        self.results = all_findings
        
        if self.logger:
            high = len([f for f in all_findings if f.severity == 'high'])
            medium = len([f for f in all_findings if f.severity == 'medium'])
            low = len([f for f in all_findings if f.severity == 'low'])
            self.logger.success(f"Vulnerability checks complete: {high} high, {medium} medium, {low} low")
        
        return all_findings
    
    def _inject_param(self, url: str, param: str, value: str) -> str:
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = [value]
            new_query = '&'.join(f"{k}={v}" for k, v in query.items())
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
        except Exception:
            return url
    
    def get_by_severity(self, severity: str) -> List[VulnFinding]:
        return [f for f in self.results if f.severity == severity]
    
    def get_by_type(self, vuln_type: str) -> List[VulnFinding]:
        return [f for f in self.results if f.vuln_type == vuln_type]


async def check_vulnerabilities(
    urls_with_params: List[Dict],
    logger=None
) -> List[VulnFinding]:
    async with HTTPClient(rate_limit=10) as http:
        checker = VulnChecker(http, logger)
        return await checker.check_all(urls_with_params)
