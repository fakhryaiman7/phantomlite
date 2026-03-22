"""
PhantomLite Vulnerability Checker Module (Enhanced)
Performs basic vulnerability checks without exploitation.
"""
import asyncio
import re
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlunparse
from utils.http import HTTPClient
from utils.dedup import Deduplicator


@dataclass
class VulnFinding:
    vuln_type: str
    url: str
    severity: str
    description: str
    evidence: str
    recommendation: str
    parameter: str = ""


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
        '//google.com',
    ]
    
    SECURITY_HEADERS = {
        'Content-Security-Policy': {
            'severity': 'medium',
            'description': 'Content Security Policy not set',
            'recommendation': 'Implement CSP header to prevent XSS and data injection attacks'
        },
        'X-Frame-Options': {
            'severity': 'medium',
            'description': 'X-Frame-Options not set',
            'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking'
        },
        'X-Content-Type-Options': {
            'severity': 'low',
            'description': 'X-Content-Type-Options not set',
            'recommendation': 'Add X-Content-Type-Options: nosniff to prevent MIME sniffing'
        },
        'Strict-Transport-Security': {
            'severity': 'medium',
            'description': 'HSTS header not set',
            'recommendation': 'Add Strict-Transport-Security header to enforce HTTPS'
        },
        'X-XSS-Protection': {
            'severity': 'low',
            'description': 'XSS protection not explicitly set',
            'recommendation': 'Set X-XSS-Protection: 1; mode=block (note: deprecated, CSP preferred)'
        },
        'Referrer-Policy': {
            'severity': 'low',
            'description': 'Referrer-Policy not set',
            'recommendation': 'Add Referrer-Policy: strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'severity': 'low',
            'description': 'Permissions-Policy not set',
            'recommendation': 'Add Permissions-Policy to control browser feature access'
        }
    }
    
    SENSITIVE_HEADERS = [
        'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version'
    ]
    
    def __init__(self, http_client: HTTPClient, logger=None):
        self.http = http_client
        self.logger = logger
        self.dedup = Deduplicator()
        self.results: List[VulnFinding] = []
        self.seen_hashes: Set[str] = set()
    
    def _add_finding(self, finding: VulnFinding):
        hash_key = f"{finding.vuln_type}:{finding.url}:{finding.parameter}"
        if hash_key not in self.seen_hashes:
            self.seen_hashes.add(hash_key)
            self.results.append(finding)
    
    async def check_reflected_xss(self, url: str, params: List[str]) -> List[VulnFinding]:
        findings = []
        
        if not params:
            return findings
        
        test_value = '<script>alert("XSS")</script>'
        
        for param in params[:5]:
            test_url = self._inject_param(url, param, test_value)
            
            try:
                resp = await self.http.get(test_url, allow_redirects=False)
                if resp and test_value in resp.body:
                    finding = VulnFinding(
                        vuln_type="Reflected XSS",
                        url=url,
                        severity="medium",
                        description=f"Parameter '{param}' reflects user input without sanitization",
                        evidence=f"Payload reflected in response",
                        recommendation=f"Sanitize and encode user input in parameter '{param}'",
                        parameter=param
                    )
                    findings.append(finding)
                    self._add_finding(finding)
            except Exception:
                pass
        
        return findings
    
    async def check_open_redirect(self, url: str, params: List[str]) -> List[VulnFinding]:
        findings = []
        
        redirect_params = ['redirect', 'url', 'next', 'return', 'callback', 'continue', 'destination', 'goto', 'to']
        
        for param in params:
            if param.lower() not in redirect_params:
                continue
            
            for payload in self.OPEN_REDIRECT_PAYLOADS[:3]:
                test_url = self._inject_param(url, param, payload)
                
                try:
                    resp = await self.http.get(test_url, allow_redirects=False)
                    if resp:
                        location = resp.headers.get('Location', '')
                        location_lower = location.lower()
                        
                        if ('evil' in location_lower or 'google' in location_lower or 
                            payload in location or location.startswith('http')):
                            finding = VulnFinding(
                                vuln_type="Open Redirect",
                                url=url,
                                severity="medium",
                                description=f"Parameter '{param}' allows arbitrary URL redirection",
                                evidence=f"Redirects to: {location[:80]}",
                                recommendation=f"Validate and whitelist allowed redirect destinations",
                                parameter=param
                            )
                            findings.append(finding)
                            self._add_finding(finding)
                except Exception:
                    pass
        
        return findings
    
    async def check_missing_headers(self, url: str) -> List[VulnFinding]:
        findings = []
        
        try:
            resp = await self.http.get(url)
            if not resp:
                return findings
            
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            
            missing = []
            weak = []
            
            for header_name, header_info in self.SECURITY_HEADERS.items():
                if header_name.lower() not in headers_lower:
                    missing.append(header_name)
            
            csp = headers_lower.get('content-security-policy', '')
            if csp and ('unsafe-inline' in csp.lower() or 'unsafe-eval' in csp.lower()):
                finding = VulnFinding(
                    vuln_type="Weak CSP",
                    url=url,
                    severity="medium",
                    description="Content-Security-Policy contains unsafe directives",
                    evidence="Contains 'unsafe-inline' or 'unsafe-eval'",
                    recommendation="Remove unsafe-inline and unsafe-eval from CSP"
                )
                findings.append(finding)
                self._add_finding(finding)
            
            for header in missing:
                header_info = self.SECURITY_HEADERS[header]
                finding = VulnFinding(
                    vuln_type="Missing Security Header",
                    url=url,
                    severity=header_info['severity'],
                    description=header_info['description'],
                    evidence=f"Header '{header}' is not set",
                    recommendation=header_info['recommendation']
                )
                findings.append(finding)
                self._add_finding(finding)
            
            for header in self.SENSITIVE_HEADERS:
                if header.lower() in headers_lower:
                    finding = VulnFinding(
                        vuln_type="Information Disclosure",
                        url=url,
                        severity="low",
                        description=f"Server exposes '{header}' header",
                        evidence=f"{header}: {headers_lower[header.lower()][:50]}",
                        recommendation=f"Configure server to remove or obfuscate '{header}' header"
                    )
                    findings.append(finding)
                    self._add_finding(finding)
        
        except Exception:
            pass
        
        return findings
    
    async def check_csrf_tokens(self, url: str, forms: List[Dict]) -> List[VulnFinding]:
        findings = []
        
        csrf_keywords = ['csrf', 'token', '_token', 'csrf_token', 'xsrf', 'nonce']
        
        for form in forms:
            inputs = form.get('inputs', [])
            input_names = [inp.get('name', '').lower() for inp in inputs]
            
            has_csrf = any(keyword in name for keyword in csrf_keywords for name in input_names)
            
            if not has_csrf and len(inputs) > 0:
                finding = VulnFinding(
                    vuln_type="Potential CSRF",
                    url=form.get('action', url) or url,
                    severity="low",
                    description="Form does not appear to have CSRF protection",
                    evidence=f"Form has {len(inputs)} inputs but no CSRF token detected",
                    recommendation="Add CSRF tokens to forms that perform state-changing operations"
                )
                findings.append(finding)
                self._add_finding(finding)
        
        return findings
    
    async def check_sqli_indicators(self, url: str, params: List[str]) -> List[VulnFinding]:
        findings = []
        
        sqli_indicators = ["'", '"', ' OR 1=1', '--', ';--']
        
        for param in params[:3]:
            for indicator in sqli_indicators[:2]:
                test_url = self._inject_param(url, param, indicator)
                
                try:
                    resp = await self.http.get(test_url, allow_redirects=False)
                    if resp:
                        body_lower = resp.body.lower()
                        
                        error_keywords = [
                            'sql', 'syntax', 'mysql', 'postgresql', 'oracle',
                            'microsoft sql', 'sqlite', 'mariadb', 'error in your sql',
                            'warning:', 'exception', 'fatal'
                        ]
                        
                        errors_found = [kw for kw in error_keywords if kw in body_lower]
                        
                        if errors_found and resp.status >= 400:
                            finding = VulnFinding(
                                vuln_type="SQL Injection Indicator",
                                url=url,
                                severity="high",
                                description=f"Parameter '{param}' may be vulnerable to SQL injection",
                                evidence=f"SQL-related errors detected: {', '.join(errors_found[:3])}",
                                recommendation=f"Use parameterized queries for parameter '{param}'",
                                parameter=param
                            )
                            findings.append(finding)
                            self._add_finding(finding)
                except Exception:
                    pass
        
        return findings
    
    async def check_ssti(self, url: str, params: List[str]) -> List[VulnFinding]:
        findings = []
        
        ssti_payloads = ['{{7*7}}', '${7*7}', '<%= 7*7 %>', '{7*7}']
        
        for param in params[:3]:
            for payload in ssti_payloads[:2]:
                test_url = self._inject_param(url, param, payload)
                
                try:
                    resp = await self.http.get(test_url)
                    if resp:
                        if '49' in resp.body:
                            finding = VulnFinding(
                                vuln_type="SSTI (Template Injection)",
                                url=url,
                                severity="high",
                                description=f"Parameter '{param}' may be vulnerable to Server-Side Template Injection",
                                evidence=f"Template expression evaluated: {payload} -> 49",
                                recommendation=f"Escape or sanitize user input in parameter '{param}'",
                                parameter=param
                            )
                            findings.append(finding)
                            self._add_finding(finding)
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
                self.check_sqli_indicators(url, params),
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    all_findings.extend(result)
        
        self.results = self.dedup.dedup_vulns(self.results)
        all_findings = self.dedup.dedup_vulns(all_findings)
        
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
