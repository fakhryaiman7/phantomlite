"""
PhantomLite Subdomain Takeover Detection Module
Checks CNAME records against known vulnerable service signatures.
"""
import asyncio
import dns.resolver
from typing import List, Dict, Optional
from dataclasses import dataclass
from modules.vuln import VulnFinding

@dataclass
class TakeoverSignature:
    service: str
    cname_patterns: List[str]
    fingerprints: List[str]
    status: str = "potential"

class TakeoverDetector:
    # Common signatures for subdomain takeovers
    # Ref: https://github.com/EdOverflow/can-i-take-over-xyz
    SIGNATURES = [
        TakeoverSignature(
            service="GitHub Pages",
            cname_patterns=[".github.io"],
            fingerprints=["There isn't a GitHub Pages site here.", "For root domains (example.com) you must create a CNAME record"]
        ),
        TakeoverSignature(
            service="Heroku",
            cname_patterns=[".herokuapp.com"],
            fingerprints=["No such app", "herokucdn.com/error-pages/no-such-app.html"]
        ),
        TakeoverSignature(
            service="Amazon S3",
            cname_patterns=[".s3.amazonaws.com", ".s3-website"],
            fingerprints=["NoSuchBucket", "The specified bucket does not exist"]
        ),
        TakeoverSignature(
            service="Shopify",
            cname_patterns=[".myshopify.com"],
            fingerprints=["Sorry, this shop is currently unavailable.", "Only one step left!"]
        ),
        TakeoverSignature(
            service="Bitbucket",
            cname_patterns=["bitbucket.io"],
            fingerprints=["Repository not found"]
        ),
        TakeoverSignature(
            service="Ghost",
            cname_patterns=[".ghost.io"],
            fingerprints=["The thing you were looking for is no longer here", "ghost.io"]
        ),
        TakeoverSignature(
            service="Fastly",
            cname_patterns=[".fastly.net"],
            fingerprints=["Fastly error: unknown domain"]
        ),
        TakeoverSignature(
            service="Zendesk",
            cname_patterns=[".zendesk.com"],
            fingerprints=["Help Center Closed"]
        ),
    ]

    def __init__(self, logger=None):
        self.logger = logger
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    async def check_takeover(self, domain: str) -> Optional[VulnFinding]:
        try:
            # Get CNAME record
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(None, self._query_cname, domain)
            
            if not answers:
                return None

            cname = str(answers[0].target).lower().rstrip('.')
            
            for sig in self.SIGNATURES:
                if any(pattern in cname for pattern in sig.cname_patterns):
                    # Potential match found based on CNAME
                    # In a full tool, we'd also check the HTTP body for the fingerprint
                    # but for this lite version, we report it as a high potential finding
                    
                    finding = VulnFinding(
                        vuln_type="Subdomain Takeover",
                        url=f"http://{domain}",
                        severity="high",
                        description=f"Domain {domain} points to {sig.service} via {cname}, but the app might be unclaimed.",
                        evidence=f"CNAME: {cname}",
                        recommendation=f"Claim the domain on {sig.service} or remove the CNAME record."
                    )
                    
                    if self.logger:
                        self.logger.warning(f"Potential Takeover: {domain} -> {sig.service}")
                    
                    return finding
                    
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            pass
        except Exception as e:
            if self.logger:
                self.logger.debug(f"DNS query failed for {domain}: {e}")
                
        return None

    def _query_cname(self, domain: str):
        try:
            return self.resolver.resolve(domain, 'CNAME')
        except:
            return None

async def run_takeover_check(domains: List[str], logger=None) -> List[VulnFinding]:
    detector = TakeoverDetector(logger)
    findings = []
    
    tasks = [detector.check_takeover(d) for d in domains]
    results = await asyncio.gather(*tasks)
    
    for r in results:
        if r:
            findings.append(r)
            
    return findings
