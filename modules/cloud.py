"""
PhantomLite Cloud Storage Scanner Module
Guesses bucket names based on the domain and checks for public access.
"""
import asyncio
import aiohttp
from typing import List, Dict, Optional
from modules.vuln import VulnFinding
from utils.http import HTTPClient

class CloudScanner:
    def __init__(self, http_client: HTTPClient, logger=None):
        self.http = http_client
        self.logger = logger
        self.findings: List[VulnFinding] = []

    async def scan_cloud_storage(self, domain: str) -> List[VulnFinding]:
        base_name = domain.split('.')[0]
        
        # Common bucket naming patterns
        suffixes = [
            "", "-static", "-assets", "-data", "-backup", "-public", 
            "-staging", "-dev", "-test", "-prod", "-logs", "-sql",
            ".static", ".assets", ".data", ".backup", ".public"
        ]
        
        bucket_names = [f"{base_name}{s}" for s in suffixes]
        
        self.logger.info(f"Scanning for cloud storage buckets for {base_name}...")
        
        tasks = []
        for name in bucket_names:
            tasks.append(self._check_s3(name))
            tasks.append(self._check_gcp(name))
            tasks.append(self._check_azure(name))
            
        results = await asyncio.gather(*tasks)
        
        current_findings = [r for r in results if r is not None]
        self.findings.extend(current_findings)
        
        return current_findings

    async def _check_s3(self, name: str) -> Optional[VulnFinding]:
        url = f"https://{name}.s3.amazonaws.com"
        try:
            resp = await self.http.get(url, timeout=5)
            if not resp:
                return None
                
            if resp.status == 200:
                if "ListBucketResult" in resp.body:
                    return VulnFinding(
                        vuln_type="Exposed S3 Bucket",
                        url=url,
                        severity="high",
                        description=f"Publicly accessible S3 bucket found: {name}",
                        evidence="HTTP 200 with ListBucketResult in body",
                        recommendation="Restrict public access to the S3 bucket via IAM policies."
                    )
            elif resp.status == 403:
                # Optionally report protected buckets if needed
                pass
        except:
            pass
        return None

    async def _check_gcp(self, name: str) -> Optional[VulnFinding]:
        url = f"https://storage.googleapis.com/{name}"
        try:
            resp = await self.http.get(url, timeout=5)
            if not resp:
                return None
                
            if resp.status == 200:
                if "ListBucketResult" in resp.body or "Items" in resp.body:
                    return VulnFinding(
                        vuln_type="Exposed GCP Bucket",
                        url=url,
                        severity="high",
                        description=f"Publicly accessible GCP bucket found: {name}",
                        evidence="HTTP 200 with directory listing content",
                        recommendation="Restrict public access to the GCP bucket."
                    )
        except:
            pass
        return None

    async def _check_azure(self, name: str) -> Optional[VulnFinding]:
        url = f"https://{name}.blob.core.windows.net"
        try:
            resp = await self.http.get(url, timeout=5)
            if not resp:
                return None
                
            # Azure usually returns 400 or something if it doesn't exist, 
            # 403 if it exists but is private, 200 if public.
            if resp.status == 200:
                return VulnFinding(
                    vuln_type="Exposed Azure Blob Storage",
                    url=url,
                    severity="high",
                    description=f"Publicly accessible Azure storage account found: {name}",
                    evidence="HTTP 200 on storage account URL",
                    recommendation="Restrict public access to the Azure storage account."
                )
        except:
            pass
        return None

async def run_cloud_scan(domain: str, logger=None) -> List[VulnFinding]:
    async with HTTPClient(rate_limit=5) as http:
        scanner = CloudScanner(http, logger)
        return await scanner.scan_cloud_storage(domain)
