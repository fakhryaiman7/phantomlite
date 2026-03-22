"""
PhantomLite Deduplication Engine
Centralized deduplication logic for all findings.
"""
import hashlib
import re
from typing import List, Dict, Set, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


@dataclass
class DedupResult:
    original: Any
    normalized_key: str
    hash_key: str


class Deduplicator:
    def __init__(self):
        self.seen_hashes: Set[str] = set()
        self.seen_urls: Set[str] = set()
        self.seen_params: Set[str] = set()
        self.seen_endpoints: Dict[str, str] = {}
        self.seen_vulns: Dict[str, Any] = {}
    
    def normalize_url(self, url: str, strip_params: bool = False) -> str:
        try:
            parsed = urlparse(url.lower().strip())
            
            scheme = parsed.scheme or 'https'
            netloc = parsed.netloc.lower()
            
            if netloc.startswith('www.'):
                netloc = netloc[4:]
            
            path = parsed.path.rstrip('/') or '/'
            path = re.sub(r'/+', '/', path)
            
            if strip_params:
                query = ''
            else:
                query = parsed.query
            
            normalized = urlunparse((
                scheme,
                netloc,
                path,
                parsed.params,
                query,
                ''
            ))
            
            return normalized
        except Exception:
            return url.lower().strip()
    
    def extract_params(self, url: str) -> Set[str]:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            return set(params.keys())
        except Exception:
            return set()
    
    def url_to_hash(self, url: str) -> str:
        normalized = self.normalize_url(url)
        return hashlib.md5(normalized.encode()).hexdigest()
    
    def endpoint_to_hash(self, path: str, base_url: str = "") -> str:
        if base_url:
            full = f"{self.normalize_url(base_url, strip_params=True)}{path}"
        else:
            full = path
        return hashlib.md5(full.encode()).hexdigest()
    
    def vuln_to_hash(self, vuln_type: str, url: str, param: str = "") -> str:
        normalized_url = self.normalize_url(url)
        key = f"{vuln_type}:{normalized_url}:{param}".lower()
        return hashlib.md5(key.encode()).hexdigest()
    
    def dedup_urls(self, urls: List[str]) -> List[str]:
        unique_urls = []
        seen = set()
        
        for url in urls:
            normalized = self.normalize_url(url)
            if normalized not in seen:
                seen.add(normalized)
                unique_urls.append(url)
        
        return unique_urls
    
    def dedup_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        unique = []
        seen = set()
        
        for ep in endpoints:
            key = self.endpoint_to_hash(
                ep.get('path', ''),
                ep.get('base_url', '')
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        
        return unique
    
    def dedup_vulns(self, findings: List[Any]) -> List[Any]:
        unique = []
        seen = set()
        
        for finding in findings:
            vuln_type = getattr(finding, 'vuln_type', 'Unknown')
            url = getattr(finding, 'url', '')
            param = ''
            
            if hasattr(finding, 'evidence'):
                param_match = re.search(r"parameter ['\"]?(\w+)['\"]?", str(finding.evidence))
                if param_match:
                    param = param_match.group(1)
            
            hash_key = self.vuln_to_hash(vuln_type, url, param)
            
            if hash_key not in seen:
                seen.add(hash_key)
                unique.append(finding)
        
        return unique
    
    def merge_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        merged = {}
        
        for ep in endpoints:
            path = ep.get('path', '')
            base = ep.get('base_url', '')
            key = f"{base}:{path}".lower()
            
            if key not in merged:
                merged[key] = {
                    'path': path,
                    'base_url': base,
                    'url': ep.get('url', ''),
                    'method': ep.get('method', 'GET'),
                    'params': set(ep.get('params', [])),
                    'has_params': len(ep.get('params', [])) > 0,
                    'is_sensitive': ep.get('is_sensitive', False),
                    'sources': [ep.get('source', 'unknown')]
                }
            else:
                merged[key]['params'].update(ep.get('params', []))
                merged[key]['has_params'] = len(merged[key]['params']) > 0
                merged[key]['is_sensitive'] = merged[key]['is_sensitive'] or ep.get('is_sensitive', False)
                merged[key]['sources'].append(ep.get('source', 'unknown'))
        
        result = []
        for key, data in merged.items():
            result.append({
                'path': data['path'],
                'base_url': data['base_url'],
                'url': data['url'] or f"{data['base_url']}{data['path']}",
                'method': data['method'],
                'params': list(data['params']),
                'has_params': data['has_params'],
                'is_sensitive': data['is_sensitive'],
                'sources': list(set(data['sources']))
            })
        
        return result
    
    def normalize_param(self, param: str) -> str:
        param = param.lower().strip()
        param = re.sub(r'[\[\]]', '', param)
        return param
    
    def is_sensitive_param(self, param: str) -> bool:
        sensitive = [
            'id', 'user', 'username', 'email', 'password', 'pass', 'pwd',
            'token', 'key', 'secret', 'auth', 'api_key', 'apikey', 'session',
            'sessionid', 'redirect', 'url', 'next', 'callback', 'file', 'path',
            'page', 'debug', 'admin', 'role', 'upload', 'data', 'content'
        ]
        normalized = self.normalize_param(param)
        return any(s in normalized for s in sensitive)
    
    def reset(self):
        self.seen_hashes.clear()
        self.seen_urls.clear()
        self.seen_params.clear()
        self.seen_endpoints.clear()
        self.seen_vulns.clear()


class ParameterExtractor:
    @staticmethod
    def extract_from_url(url: str) -> Dict[str, str]:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            return {k: v[0] if v else '' for k, v in params.items()}
        except Exception:
            return {}
    
    @staticmethod
    def extract_from_forms(html: str) -> List[Dict]:
        forms = []
        
        form_pattern = re.compile(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'][^>]*>',
            re.IGNORECASE
        )
        
        input_pattern = re.compile(
            r'<input[^>]*name=["\']([^"\']*)["\'][^>]*(?:value=["\']([^"\']*)["\'])?[^>]*type=["\']([^"\']*)["\'][^>]*>',
            re.IGNORECASE
        )
        
        input_pattern2 = re.compile(
            r'<input[^>]*type=["\']([^"\']*)["\'][^>]*name=["\']([^"\']*)["\'][^>]*(?:value=["\']([^"\']*)["\'])?[^>]*>',
            re.IGNORECASE
        )
        
        select_pattern = re.compile(
            r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>',
            re.IGNORECASE
        )
        
        textarea_pattern = re.compile(
            r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>',
            re.IGNORECASE
        )
        
        for form_match in form_pattern.finditer(html):
            form_action = form_match.group(1) or ''
            form_method = (form_match.group(2) or 'get').upper()
            
            inputs = []
            form_start = form_match.start()
            form_end = form_match.end() + 10000
            
            for inp_match in input_pattern.finditer(html[form_start:form_end]):
                inp_name = inp_match.group(1)
                inp_type = inp_match.group(3).lower() if inp_match.group(3) else 'text'
                if inp_name:
                    inputs.append({
                        'name': inp_name,
                        'type': inp_type,
                        'value': inp_match.group(2) or ''
                    })
            
            for inp_match in input_pattern2.finditer(html[form_start:form_end]):
                inp_type = inp_match.group(1).lower() if inp_match.group(1) else 'text'
                inp_name = inp_match.group(2)
                if inp_name and inp_type != 'submit':
                    inputs.append({
                        'name': inp_name,
                        'type': inp_type,
                        'value': inp_match.group(3) or ''
                    })
            
            for sel_match in select_pattern.finditer(html[form_start:form_end]):
                sel_name = sel_match.group(1)
                if sel_name:
                    inputs.append({
                        'name': sel_name,
                        'type': 'select',
                        'value': ''
                    })
            
            for ta_match in textarea_pattern.finditer(html[form_start:form_end]):
                ta_name = ta_match.group(1)
                if ta_name:
                    inputs.append({
                        'name': ta_name,
                        'type': 'textarea',
                        'value': ''
                    })
            
            forms.append({
                'action': form_action,
                'method': form_method,
                'inputs': inputs
            })
        
        return forms
    
    @staticmethod
    def is_login_form(inputs: List[Dict]) -> bool:
        has_password = any(
            inp.get('type', '').lower() == 'password' 
            for inp in inputs
        )
        has_userfield = any(
            any(x in inp.get('name', '').lower() for x in ['user', 'email', 'login', 'username'])
            for inp in inputs
        )
        return has_password and has_userfield
    
    @staticmethod
    def is_upload_form(inputs: List[Dict]) -> bool:
        return any(
            inp.get('type', '').lower() == 'file'
            for inp in inputs
        )


def deduplicate_all(
    urls: List[str] = None,
    endpoints: List[Dict] = None,
    findings: List[Any] = None
) -> Dict[str, Any]:
    dedup = Deduplicator()
    
    result = {
        'urls': [],
        'endpoints': [],
        'findings': []
    }
    
    if urls:
        result['urls'] = dedup.dedup_urls(urls)
    
    if endpoints:
        merged = dedup.merge_endpoints(endpoints)
        result['endpoints'] = dedup.dedup_endpoints(merged)
    
    if findings:
        result['findings'] = dedup.dedup_vulns(findings)
    
    return result
