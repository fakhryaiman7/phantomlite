"""
PhantomLite Template-based Vulnerability Scanner (Nuclei-lite)
Uses predefined templates to detect common misconfigurations and exposed sensitive files.
"""
import asyncio
import re
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from utils.http import HTTPClient
from modules.vuln import VulnFinding


@dataclass
class ScanTemplate:
    id: str
    name: str
    severity: str
    path: str
    match_type: str  # 'word', 'regex', 'status'
    matches: List[str]
    description: str
    recommendation: str


class TemplateScanner:
    # Built-in templates for common sensitive files and misconfigurations
    TEMPLATES = [
        ScanTemplate(
            id="exposed-git",
            name="Exposed Git Repository",
            severity="high",
            path="/.git/config",
            match_type="word",
            matches=["[core]", "[remote", "url ="],
            description="Exposed Git directory allows full source code access",
            recommendation="Restrict access to .git directory or remove it from web root"
        ),
        ScanTemplate(
            id="exposed-env",
            name="Exposed ENV File",
            severity="high",
            path="/.env",
            match_type="regex",
            matches=[r"DB_PASSWORD", r"DB_USERNAME", r"API_KEY", r"AWS_ACCESS_KEY_ID"],
            description="Exposed environment variables file contains sensitive credentials",
            recommendation="Move sensitive variables to system environment or restrict access"
        ),
        ScanTemplate(
            id="exposed-config",
            name="Exposed PHP Config",
            severity="high",
            path="/config.php.bak",
            match_type="word",
            matches=["<?php", "define(", "DB_PASSWORD"],
            description="Exposed backup configuration file with database credentials",
            recommendation="Remove backup files or restrict access"
        ),
        ScanTemplate(
            id="django-debug",
            name="Django Debug Mode",
            severity="medium",
            path="/",
            match_type="word",
            matches=["Django Version", "DEBUG = True", "DisallowedHost"],
            description="Django debug mode is enabled, exposing detailed system information",
            recommendation="Set DEBUG = False in Django settings"
        ),
        ScanTemplate(
            id="phpinfo",
            name="PHP Information Page",
            severity="low",
            path="/phpinfo.php",
            match_type="word",
            matches=["phpinfo()", "PHP Version", "System"],
            description="Exposed phpinfo page discloses server details",
            recommendation="Remove the phpinfo.php file from the web root"
        ),
        ScanTemplate(
            id="springboot-actuator",
            name="Spring Boot Actuator",
            severity="medium",
            path="/actuator/env",
            match_type="word",
            matches=["activeProfiles", "propertySources", "systemProperties"],
            description="Spring Boot Actuator endpoints are exposed, leaking environment info",
            recommendation="Disable actuator endpoints or restrict access with authentication"
        ),
        ScanTemplate(
            id="wordpress-license",
            name="WordPress License Disclosure",
            severity="low",
            path="/license.txt",
            match_type="word",
            matches=["WordPress", "GNU General Public License"],
            description="WordPress license file discloses CMS version",
            recommendation="Remove license.txt to reduce information disclosure"
        ),
        ScanTemplate(
            id="exposed-aws-keys",
            name="Exposed AWS Credentials in JS",
            severity="high",
            path="/static/js/bundle.js", # Generic path, scanner will try various JS files
            match_type="regex",
            matches=[r"AKIA[0-9A-Z]{16}"],
            description="AWS Access Key detected in JavaScript file",
            recommendation="Revoke the exposed key and use IAM roles instead"
        ),
        ScanTemplate(
            id="exposed-htaccess",
            name="Exposed .htaccess File",
            severity="low",
            path="/.htaccess",
            match_type="word",
            matches=["RewriteEngine", "Options", "<Files"],
            description="Server configuration file .htaccess is exposed",
            recommendation="Restrict access to .htaccess using server configuration"
        ),
    ]
    
    def __init__(self, http_client: HTTPClient, logger=None):
        self.http = http_client
        self.logger = logger
        self.findings: List[VulnFinding] = []
    
    async def scan_target_with_templates(self, base_url: str) -> List[VulnFinding]:
        if self.logger:
            self.logger.scan(f"Running template-based scan on {base_url}...")
            
        tasks = []
        for template in self.TEMPLATES:
            tasks.append(self._run_template(base_url, template))
            
        results = await asyncio.gather(*tasks)
        
        target_findings = [r for r in results if r is not None]
        self.findings.extend(target_findings)
        
        return target_findings
    
    async def _run_template(self, base_url: str, template: ScanTemplate) -> Optional[VulnFinding]:
        url = base_url.rstrip('/') + template.path
        
        try:
            resp = await self.http.get(url, timeout=10)
            if not resp or resp.status != 200:
                return None
            
            content = resp.body
            is_match = False
            
            if template.match_type == 'word':
                if all(word in content for word in template.matches):
                    is_match = True
            elif template.match_type == 'regex':
                if any(re.search(pattern, content) for pattern in template.matches):
                    is_match = True
            elif template.match_type == 'status':
                if str(resp.status) in template.matches:
                    is_match = True
            
            if is_match:
                finding = VulnFinding(
                    vuln_type=f"Template: {template.name}",
                    url=url,
                    severity=template.severity,
                    description=template.description,
                    evidence=f"Matched template {template.id} pattern(s)",
                    recommendation=template.recommendation
                )
                
                if self.logger:
                    self.logger.warning(f"Found {template.name} at {url}")
                    
                return finding
                
        except Exception:
            pass
            
        return None


async def run_template_scan(target_urls: List[str], logger=None) -> List[VulnFinding]:
    async with HTTPClient(rate_limit=10) as http:
        scanner = TemplateScanner(http, logger)
        all_findings = []
        
        for url in target_urls:
            findings = await scanner.scan_target_with_templates(url)
            all_findings.extend(findings)
            
        return all_findings
