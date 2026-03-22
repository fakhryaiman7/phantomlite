"""
PhantomLite Dynamic XSS Scanner Module
Tests discovered parameters for reflection vulnerabilities.
"""
import asyncio
import aiohttp
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from modules.vuln import VulnFinding
from utils.http import HTTPClient

class XSSScanner:
    # Safe payloads that won't cause harm but are easy to detect
    PAYLOADS = [
        "<script>confirm(1)</script>",
        "\"-confirm(1)-\"",
        "'-confirm(1)-'",
        "<img src=x onerror=confirm(1)>",
        "javascript:confirm(1)"
    ]

    def __init__(self, http_client: HTTPClient, logger=None):
        self.http = http_client
        self.logger = logger

    async def scan_endpoint(self, endpoint: Dict[str, Any]) -> List[VulnFinding]:
        findings = []
        url = endpoint.get('url', '')
        params = endpoint.get('params', [])
        
        if not params or not url:
            return []

        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        
        for param in params:
            for payload in self.PAYLOADS:
                # Create a copy of query params and inject payload
                test_query = query.copy()
                test_query[param] = [payload]
                
                # Rebuild URL with injected payload
                new_query = urlencode(test_query, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))
                
                try:
                    resp = await self.http.get(test_url, timeout=10)
                    if resp and payload in resp.body:
                        self.logger.warning(f"XSS Reflected: {test_url}")
                        findings.append(VulnFinding(
                            vuln_type="Reflected XSS",
                            url=test_url,
                            severity="high",
                            parameter=param,
                            description=f"Potential Reflected XSS found in parameter '{param}'.",
                            evidence=f"Payload '{payload}' was reflected in the response body.",
                            recommendation="Sanitize user input and use context-aware output encoding."
                        ))
                        # Only report one payload per parameter to reduce noise
                        break
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"XSS scan error for {test_url}: {e}")
        
        return findings

async def run_xss_scan(endpoints: List[Dict[str, Any]], logger=None) -> List[VulnFinding]:
    async with HTTPClient(rate_limit=10) as http:
        scanner = XSSScanner(http, logger)
        all_findings = []
        
        # Filter for endpoints with parameters
        testable = [ep for ep in endpoints if ep.get('params')]
        
        # Limit to top 20 endpoints for performance in "lite" version
        for ep in testable[:20]:
            findings = await scanner.scan_endpoint(ep)
            all_findings.extend(findings)
            
        return all_findings
