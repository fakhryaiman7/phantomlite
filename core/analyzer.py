"""
PhantomLite Smart Analyzer Module (Enhanced)
Analyzes collected data to identify high-value targets and generate actionable suggestions.
"""
from typing import List, Dict, Set, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs
from utils.dedup import Deduplicator


@dataclass
class AnalysisResult:
    target: str
    target_type: str
    score: int
    suggestions: List[str]
    details: Dict[str, Any] = field(default_factory=dict)
    vuln_type: str = ""


class HeuristicEngine:
    IDOR_PATTERNS = [
        (['id', 'user_id', 'post_id', 'item_id', 'product_id', 'category_id', 'order_id', 'transaction_id'], 
         "ID parameter detected - test for IDOR vulnerability"),
        (['uid', 'pid', 'cid', 'eid', 'aid', 'sid', 'rid', 'bid'],
         "Numeric ID parameter - test for IDOR by manipulating the value"),
        (['profile', 'account', 'user', 'member', 'profile_id'],
         "User-related ID - test for horizontal/vertical privilege escalation"),
    ]
    
    XSS_PATTERNS = [
        (['q', 'query', 'search', 'term', 'keyword', 's', 'find', 'filter'],
         "Search/filter parameter - test for reflected XSS"),
        (['comment', 'message', 'msg', 'content', 'body', 'text', 'desc', 'description'],
         "Text input parameter - test for stored XSS"),
        (['name', 'title', 'subject', 'headline'],
         "Name field - test for XSS in displayed content"),
        (['email', 'url', 'link', 'website'],
         "Input may be reflected - test for XSS"),
    ]
    
    SSRF_PATTERNS = [
        (['url', 'uri', 'link', 'src', 'source', 'dest', 'redirect', 'next', 'data'],
         "URL parameter detected - test for SSRF vulnerability"),
        (['host', 'port', 'path', 'callback', 'return', 'page'],
         "Host-related parameter - test for SSRF by providing internal URLs"),
        (['ip', 'addr', 'server', 'domain', 'hostname'],
         "Server address parameter - test for SSRF against internal services"),
    ]
    
    OPEN_REDIRECT_PATTERNS = [
        (['redirect', 'url', 'next', 'return', 'continue', 'callback', 'destination'],
         "Redirect parameter - test for open redirect vulnerability"),
        (['goto', 'to', 'out', 'view', 'destination'],
         "Navigation parameter - test for open redirect"),
        (['ref', 'referer', 'forward', 'back'],
         "Referrer parameter - test for redirect manipulation"),
    ]
    
    LFI_PATTERNS = [
        (['file', 'path', 'include', 'require', 'load', 'template', 'view', 'page', 'doc'],
         "File-related parameter - test for LFI/RFI vulnerability"),
        (['dir', 'folder', 'directory', 'folder', 'prefix', 'suffix'],
         "Directory parameter - test for path traversal"),
        (['name', 'filename', 'filepath', 'file_path', 'document'],
         "Filename parameter - test for LFI with null byte injection"),
    ]
    
    SQLI_PATTERNS = [
        (['id', 'sort', 'order', 'filter', 'search', 'query', 'page', 'per_page'],
         "Query parameter - test for SQL injection"),
        (['user', 'name', 'cat', 'type', 'status', 'role'],
         "Filter parameter - test for boolean-based SQL injection"),
    ]
    
    SENSITIVE_PATHS = [
        ('admin', 'Admin panel - test for authentication bypass and IDOR'),
        ('login', 'Login page - test for credential stuffing and brute force'),
        ('auth', 'Authentication endpoint - test for auth bypass vulnerabilities'),
        ('api', 'API endpoint - test for authorization issues and rate limiting'),
        ('upload', 'File upload functionality - test for arbitrary file upload'),
        ('dashboard', 'Dashboard - test for information disclosure and IDOR'),
        ('config', 'Configuration page - may expose sensitive settings'),
        ('backup', 'Backup directory - test for backup file disclosure'),
        ('debug', 'Debug endpoint - test for information disclosure'),
        ('test', 'Test endpoint - test for debug functionality'),
        ('wp-admin', 'WordPress admin - test for authentication bypass'),
        ('phpmyadmin', 'phpMyAdmin - test for unauthorized access'),
        ('.env', 'Environment file - test for credential disclosure'),
        ('.git', 'Git repository - test for source code disclosure'),
    ]
    
    SENSITIVE_PARAMS = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'auth', 'private', 'credential', 'access_token', 'refresh_token',
        'ssn', 'credit_card', 'cvv', 'pin'
    ]
    
    def __init__(self, logger=None):
        self.logger = logger
        self.dedup = Deduplicator()
        self.results: List[AnalysisResult] = []
    
    def analyze_endpoint(self, endpoint: Dict) -> AnalysisResult:
        path = endpoint.get('path', '')
        params = endpoint.get('params', [])
        url = endpoint.get('url', '')
        method = endpoint.get('method', 'GET')
        is_sensitive = endpoint.get('is_sensitive', False)
        
        suggestions = []
        score = 0
        target_type = "General"
        
        path_lower = path.lower()
        params_lower = [p.lower() for p in params]
        
        for patterns, suggestion in self.IDOR_PATTERNS:
            if any(p in params_lower for p in patterns):
                suggestions.append(f"[!] {suggestion}")
                score += 40
                if not target_type or target_type == "General":
                    target_type = "IDOR Target"
                break
        
        for patterns, suggestion in self.XSS_PATTERNS:
            if any(p in params_lower for p in patterns):
                suggestions.append(f"[!] {suggestion}")
                score += 35
                if target_type == "General":
                    target_type = "XSS Target"
                break
        
        for patterns, suggestion in self.SSRF_PATTERNS:
            if any(p in params_lower for p in patterns):
                suggestions.append(f"[!] {suggestion}")
                score += 45
                if target_type == "General":
                    target_type = "SSRF Target"
                break
        
        for patterns, suggestion in self.OPEN_REDIRECT_PATTERNS:
            if any(p in params_lower for p in patterns):
                suggestions.append(f"[!] {suggestion}")
                score += 30
                if target_type == "General":
                    target_type = "Open Redirect Target"
                break
        
        for patterns, suggestion in self.LFI_PATTERNS:
            if any(p in params_lower for p in patterns):
                suggestions.append(f"[!] {suggestion}")
                score += 50
                if target_type == "General":
                    target_type = "LFI Target"
                break
        
        for patterns, suggestion in self.SQLI_PATTERNS:
            if any(p in params_lower for p in patterns):
                suggestions.append(f"[!] {suggestion}")
                score += 45
                if target_type == "General":
                    target_type = "SQLi Target"
                break
        
        for sensitive_path, suggestion in self.SENSITIVE_PATHS:
            if sensitive_path in path_lower:
                suggestions.append(f"[!] {suggestion}")
                score += 30
                if target_type == "General":
                    target_type = "Sensitive Endpoint"
                break
        
        for sensitive_param in self.SENSITIVE_PARAMS:
            if sensitive_param in params_lower:
                suggestions.append(f"[!] Sensitive parameter '{sensitive_param}' - handle with care")
                score += 20
        
        if endpoint.get('has_params') and len(params) > 3:
            suggestions.append("[!] Multiple parameters - test for parameter pollution")
            score += 20
        
        if method == 'POST':
            suggestions.append("[!] POST endpoint - test for CSRF and parameter tampering")
            score += 15
        
        if 'api' in path_lower or 'graphql' in path_lower or 'rest' in path_lower:
            suggestions.append("[!] API endpoint - test for authorization, rate limiting, and IDOR")
            score += 50
            target_type = "API Endpoint"
        
        if score == 0 and is_sensitive:
            score = 30
            target_type = "Sensitive Path"
        
        score = min(score, 100)
        
        return AnalysisResult(
            target=url or path,
            target_type=target_type,
            score=score,
            suggestions=suggestions,
            details={
                'path': path,
                'method': method,
                'params': params,
                'has_params': endpoint.get('has_params', False),
                'is_sensitive': is_sensitive,
                'sources': endpoint.get('sources', ['unknown'])
            }
        )
    
    def analyze_form(self, form: Dict, base_url: str) -> AnalysisResult:
        action = form.get('action', '')
        inputs = form.get('inputs', [])
        method = form.get('method', 'GET').upper()
        
        input_names = [inp.get('name', '').lower() for inp in inputs]
        input_types = [inp.get('type', 'text').lower() for inp in inputs]
        
        suggestions = []
        score = 0
        target_type = "Form"
        
        has_password = any(t == 'password' for t in input_types)
        has_file = any(t == 'file' for t in input_types)
        has_email = any('email' in name for name in input_names)
        
        if has_password:
            suggestions.append("[!] Login form detected - test for credential stuffing, brute force, and account takeover")
            score += 70
            target_type = "Login Form"
        
        if has_file:
            suggestions.append("[!] File upload form - test for arbitrary file upload, webshell upload, and mime-type bypass")
            score += 90
            target_type = "File Upload"
        
        if has_email:
            suggestions.append("[!] Email field - test for email enumeration via response differences")
            score += 20
        
        csrf_safe = any('csrf' in name or 'token' in name or 'nonce' in name for name in input_names)
        if not csrf_safe:
            suggestions.append("[!] No CSRF protection detected - forms may be vulnerable to CSRF attacks")
            score += 25
        
        text_inputs = [name for name, t in zip(input_names, input_types) 
                       if t in ['text', 'search', 'textarea']]
        if text_inputs:
            suggestions.append("[!] Text inputs detected - test for XSS and injection vulnerabilities")
            score += 30
        
        hidden_inputs = any(t == 'hidden' for t in input_types)
        if hidden_inputs:
            suggestions.append("[!] Hidden inputs detected - test for parameter tampering")
            score += 15
        
        return AnalysisResult(
            target=action or base_url,
            target_type=target_type,
            score=score,
            suggestions=suggestions,
            details={
                'method': method,
                'inputs': inputs,
                'input_count': len(inputs),
                'has_password': has_password,
                'has_file': has_file
            }
        )
    
    def analyze_all(
        self,
        endpoints: List[Dict],
        forms: List[Dict] = None,
        vuln_findings: List = None,
        js_endpoints: List[Dict] = None
    ) -> List[AnalysisResult]:
        results = []
        
        for endpoint in endpoints:
            result = self.analyze_endpoint(endpoint)
            results.append(result)
        
        if forms:
            for form in forms:
                result = self.analyze_form(form, '')
                results.append(result)
        
        if js_endpoints:
            for endpoint in js_endpoints:
                result = self.analyze_endpoint({
                    **endpoint,
                    'url': endpoint.get('path', ''),
                    'has_params': False,
                    'is_sensitive': any(kw in endpoint.get('path', '').lower() 
                                        for kw in ['admin', 'api', 'auth', 'upload', 'debug'])
                })
                results.append(result)
        
        if vuln_findings:
            for finding in vuln_findings:
                vuln_type = getattr(finding, 'vuln_type', 'Unknown')
                severity = getattr(finding, 'severity', 'low')
                
                severity_score = {'high': 80, 'medium': 50, 'low': 30}.get(severity, 30)
                
                results.append(AnalysisResult(
                    target=getattr(finding, 'url', ''),
                    target_type=vuln_type,
                    score=severity_score,
                    suggestions=[f"[!] {getattr(finding, 'recommendation', 'Review and remediate')}"],
                    details={
                        'severity': severity,
                        'description': getattr(finding, 'description', ''),
                        'evidence': getattr(finding, 'evidence', ''),
                        'parameter': getattr(finding, 'parameter', '')
                    },
                    vuln_type=vuln_type
                ))
        
        deduplicated = self._deduplicate_results(results)
        
        if self.logger:
            high_value = [r for r in deduplicated if r.score >= 50]
            self.logger.success(f"Analysis complete: {len(deduplicated)} targets, {len(high_value)} high-value")
        
        return deduplicated
    
    def _deduplicate_results(self, results: List[AnalysisResult]) -> List[AnalysisResult]:
        seen = {}
        unique = []
        
        for result in results:
            key = f"{result.target}:{result.target_type}"
            if key not in seen or seen[key].score < result.score:
                seen[key] = result
        
        return list(seen.values())
    
    def get_high_value_targets(self, results: List[AnalysisResult], threshold: int = 40) -> List[AnalysisResult]:
        return [r for r in results if r.score >= threshold]
    
    def get_suggestions_by_category(self, results: List[AnalysisResult]) -> Dict[str, List[str]]:
        categories = {
            'IDOR': [],
            'XSS': [],
            'SQLi': [],
            'Open Redirect': [],
            'SSRF': [],
            'LFI': [],
            'File Upload': [],
            'CSRF': [],
            'API': [],
            'Other': []
        }
        
        for result in results:
            target_type = result.target_type.lower()
            
            if 'idor' in target_type:
                categories['IDOR'].extend(result.suggestions)
            elif 'xss' in target_type:
                categories['XSS'].extend(result.suggestions)
            elif 'sqli' in target_type or 'sql' in target_type:
                categories['SQLi'].extend(result.suggestions)
            elif 'redirect' in target_type:
                categories['Open Redirect'].extend(result.suggestions)
            elif 'ssrf' in target_type:
                categories['SSRF'].extend(result.suggestions)
            elif 'lfi' in target_type or 'rfi' in target_type:
                categories['LFI'].extend(result.suggestions)
            elif 'upload' in target_type:
                categories['File Upload'].extend(result.suggestions)
            elif 'csrf' in target_type:
                categories['CSRF'].extend(result.suggestions)
            elif 'api' in target_type:
                categories['API'].extend(result.suggestions)
            else:
                categories['Other'].extend(result.suggestions)
        
        return {k: v for k, v in categories.items() if v}


class Analyzer:
    def __init__(self, logger=None):
        self.logger = logger
        self.heuristic = HeuristicEngine(logger)
    
    def analyze(
        self,
        endpoints: List[Dict],
        forms: List[Dict] = None,
        vuln_findings: List = None,
        js_endpoints: List[Dict] = None
    ) -> List[AnalysisResult]:
        return self.heuristic.analyze_all(endpoints, forms, vuln_findings, js_endpoints)
    
    def get_high_value_targets(self, results: List[AnalysisResult], threshold: int = 40) -> List[AnalysisResult]:
        return self.heuristic.get_high_value_targets(results, threshold)
    
    def get_suggestions(self, results: List[AnalysisResult]) -> Dict[str, List[str]]:
        return self.heuristic.get_suggestions_by_category(results)
