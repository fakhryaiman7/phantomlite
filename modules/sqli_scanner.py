"""
PhantomLite Dynamic SQL Injection Scanner Module
Tests discovered parameters for error-based SQLi vulnerabilities.
"""
import asyncio
import aiohttp
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from modules.vuln import VulnFinding
from utils.http import HTTPClient

class SQLiScanner:
    # Error indicators for common databases
    ERROR_SIGNATURES = [
        "sql syntax", "mysql_fetch", "native client", "odbcmysql",
        "oracle error", "postgresql error", "sqlite3.error",
        "syntax error at or near", "unclosed quotation mark",
        "valid mysql result", "warning: mysql_", "supplied argument is not a valid mysql",
        "microsoft ole db provider", "you have an error in your sql syntax"
    ]

    # Simple payloads that trigger syntax errors
    PAYLOADS = ["'", "\"", "\\", "') OR 1=1--", "\") OR 1=1--"]

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
                test_query = query.copy()
                test_query[param] = [payload]
                
                new_query = urlencode(test_query, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))
                
                try:
                    resp = await self.http.get(test_url, timeout=10)
                    if not resp:
                        continue
                        
                    body_lower = resp.body.lower()
                    for sig in self.ERROR_SIGNATURES:
                        if sig in body_lower:
                            self.logger.warning(f"SQLi Potential: {test_url}")
                            findings.append(VulnFinding(
                                vuln_type="Error-based SQL Injection",
                                url=test_url,
                                severity="critical",
                                parameter=param,
                                description=f"Potential SQL Injection triggered by parameter '{param}'.",
                                evidence=f"Payload '{payload}' triggered SQL error signature: '{sig}'",
                                recommendation="Use parameterized queries (prepared statements) and proper ORM abstractions."
                            ))
                            break
                    
                    if findings:
                        break # Stop if a vuln is found for this param
                        
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"SQLi scan error for {test_url}: {e}")
        
        return findings

async def run_sqli_scan(endpoints: List[Dict[str, Any]], logger=None) -> List[VulnFinding]:
    async with HTTPClient(rate_limit=5) as http:
        scanner = SQLiScanner(http, logger)
        all_findings = []
        
        testable = [ep for ep in endpoints if ep.get('params')]
        
        for ep in testable[:15]: # Limit for performance
            findings = await scanner.scan_endpoint(ep)
            all_findings.extend(findings)
            
        return all_findings
