"""
PhantomLite Analyzer Module
Analyzes collected data to identify high-value targets and potential vulnerabilities.
"""
from typing import List, Dict, Set, Any, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs
from utils.helpers import is_login_form, has_input_fields, is_sensitive_path, is_sensitive_param


@dataclass
class AnalysisResult:
    target: str
    target_type: str
    score: int
    suggestions: List[str]
    details: Dict[str, Any]


class Analyzer:
    def __init__(self, logger=None):
        self.logger = logger
        self.results: List[AnalysisResult] = []
    
    def analyze_crawl_results(self, crawl_results: List) -> List[AnalysisResult]:
        if self.logger:
            self.logger.scan("Analyzing crawled pages...")
        
        results = []
        
        for result in crawl_results:
            target_type = self._determine_type(result)
            score = self._calculate_score(result)
            suggestions = self._generate_suggestions(result, target_type)
            
            analysis = AnalysisResult(
                target=result.url if hasattr(result, 'url') else str(result),
                target_type=target_type,
                score=score,
                suggestions=suggestions,
                details={
                    'parameters': list(result.parameters) if hasattr(result, 'parameters') else [],
                    'forms': len(result.forms) if hasattr(result, 'forms') else 0,
                    'inputs': len(result.inputs) if hasattr(result, 'inputs') else 0,
                    'is_sensitive': result.is_sensitive if hasattr(result, 'is_sensitive') else False,
                    'title': result.title if hasattr(result, 'title') else None
                }
            )
            
            results.append(analysis)
        
        results.sort(key=lambda x: x.score, reverse=True)
        
        if self.logger:
            self.logger.success(f"Analysis complete: {len(results)} targets analyzed")
        
        return results
    
    def analyze_endpoints(self, endpoints: List[Dict]) -> List[AnalysisResult]:
        if self.logger:
            self.logger.scan("Analyzing endpoints...")
        
        results = []
        
        for endpoint in endpoints:
            params = endpoint.get('params', [])
            is_sensitive = endpoint.get('is_sensitive', False)
            path = endpoint.get('path', '')
            
            score = 0
            suggestions = []
            
            if any(p in ['id', 'user_id', 'post_id', 'item_id'] for p in params):
                score += 40
                suggestions.append("Test for IDOR vulnerability - manipulate ID parameters")
            
            if any(p in ['redirect', 'url', 'next', 'return'] for p in params):
                score += 30
                suggestions.append("Test for Open Redirect - check redirect handling")
            
            if any(p in ['search', 'query', 'filter', 'sort'] for p in params):
                score += 25
                suggestions.append("Test for SSRF/Injection - probe parameter handling")
            
            if any(p in ['file', 'path', 'include', 'require'] for p in params):
                score += 50
                suggestions.append("Test for LFI/RFI - check file inclusion")
            
            if len(params) > 5:
                score += 30
                suggestions.append("Many parameters detected - perform parameter pollution tests")
            
            if 'admin' in path or 'api' in path:
                score += 50
                suggestions.append("Sensitive endpoint discovered - investigate for auth bypass")
            
            if endpoint.get('method', '').upper() == 'POST':
                score += 20
                suggestions.append("POST endpoint - test for CSRF and parameter tampering")
            
            analysis = AnalysisResult(
                target=endpoint.get('url', ''),
                target_type=self._classify_endpoint_type(path, params),
                score=score,
                suggestions=suggestions,
                details={
                    'path': path,
                    'method': endpoint.get('method', 'GET'),
                    'parameters': params,
                    'is_sensitive': is_sensitive
                }
            )
            
            results.append(analysis)
        
        results.sort(key=lambda x: x.score, reverse=True)
        
        if self.logger:
            self.logger.success(f"Endpoint analysis complete: {len(results)} endpoints analyzed")
        
        return results
    
    def analyze_forms(self, forms: List[Dict], base_url: str) -> List[AnalysisResult]:
        if self.logger:
            self.logger.scan("Analyzing forms...")
        
        results = []
        
        for form in forms:
            action = form.get('action', '')
            inputs = form.get('inputs', [])
            method = form.get('method', 'GET').upper()
            
            score = 0
            suggestions = []
            
            input_names = [inp.get('name', '').lower() for inp in inputs]
            
            if any('password' in name for name in input_names):
                score += 50
                suggestions.append("Password field detected - test for credential stuffing and brute force")
                suggestions.append("Check for proper password policy enforcement")
            
            if any('email' in name or 'mail' in name for name in input_names):
                score += 30
                suggestions.append("Email field detected - test for email enumeration")
            
            if any('username' in name or 'user' in name for name in input_names):
                score += 30
                suggestions.append("Username field detected - test for username enumeration")
            
            if 'token' not in ' '.join(input_names) and 'csrf' not in ' '.join(input_names):
                score += 25
                suggestions.append("No CSRF token detected - forms may be vulnerable to CSRF")
            
            if method == 'POST' and len(inputs) > 0:
                score += 20
                suggestions.append("POST form without CSRF protection - potential CSRF vulnerability")
            
            for inp in inputs:
                inp_name = inp.get('name', '').lower()
                if any(xss_indicator in inp_name for xss_indicator in ['comment', 'message', 'content', 'body', 'text']):
                    score += 35
                    suggestions.append(f"Text input '{inp.get('name')}' - potential XSS vector")
            
            analysis = AnalysisResult(
                target=action or base_url,
                target_type="Form",
                score=score,
                suggestions=suggestions,
                details={
                    'method': method,
                    'inputs': inputs,
                    'input_count': len(inputs)
                }
            )
            
            results.append(analysis)
        
        results.sort(key=lambda x: x.score, reverse=True)
        
        if self.logger:
            self.logger.success(f"Form analysis complete: {len(results)} forms analyzed")
        
        return results
    
    def identify_high_value_targets(
        self,
        analysis_results: List[AnalysisResult],
        vuln_findings: List = None
    ) -> List[AnalysisResult]:
        high_value = []
        
        for result in analysis_results:
            if result.score >= 40:
                high_value.append(result)
        
        if vuln_findings:
            for finding in vuln_findings:
                if hasattr(finding, 'severity') and finding.severity in ['high', 'medium']:
                    high_value.append(AnalysisResult(
                        target=finding.url,
                        target_type=finding.vuln_type,
                        score=80 if finding.severity == 'high' else 50,
                        suggestions=[finding.recommendation],
                        details={'finding': str(finding)}
                    ))
        
        high_value.sort(key=lambda x: x.score, reverse=True)
        
        return high_value[:20]
    
    def _determine_type(self, result) -> str:
        url = result.url if hasattr(result, 'url') else str(result)
        path = urlparse(url).path.lower()
        
        if 'login' in path or 'signin' in path:
            return "Login Page"
        if 'admin' in path or 'dashboard' in path:
            return "Admin Panel"
        if 'api' in path:
            return "API Endpoint"
        if 'search' in path or 'query' in path:
            return "Search Interface"
        if 'upload' in path or 'file' in path:
            return "File Upload"
        if 'register' in path or 'signup' in path:
            return "Registration Page"
        if 'profile' in path or 'account' in path:
            return "User Profile"
        if 'password' in path or 'reset' in path:
            return "Password Recovery"
        
        if hasattr(result, 'forms') and len(result.forms) > 0:
            return "Form Page"
        if hasattr(result, 'parameters') and len(result.parameters) > 0:
            return "Parameterized Page"
        
        return "Standard Page"
    
    def _calculate_score(self, result) -> int:
        score = 0
        
        if hasattr(result, 'is_sensitive') and result.is_sensitive:
            score += 50
        
        if hasattr(result, 'forms') and len(result.forms) > 0:
            score += 30
        
        if hasattr(result, 'inputs') and len(result.inputs) > 0:
            score += 20 * min(len(result.inputs), 5)
        
        if hasattr(result, 'parameters'):
            params = result.parameters
            score += 40 if len(params) >= 3 else 20 * len(params)
            
            for param in params:
                if is_sensitive_param(param):
                    score += 20
        
        if hasattr(result, 'url'):
            path = urlparse(result.url).path
            if any(kw in path for kw in ['admin', 'api', 'login', 'auth', 'dashboard']):
                score += 30
        
        return min(score, 100)
    
    def _generate_suggestions(self, result, target_type: str) -> List[str]:
        suggestions = []
        
        if target_type == "Login Page":
            suggestions.append("Test for SQL injection in login form")
            suggestions.append("Check for brute force protection")
            suggestions.append("Look for credential stuffing protections")
        
        if target_type == "Admin Panel":
            suggestions.append("Test for authentication bypass")
            suggestions.append("Check for IDOR in admin functions")
            suggestions.append("Look for privilege escalation vectors")
        
        if target_type == "API Endpoint":
            suggestions.append("Test for rate limiting")
            suggestions.append("Check for authorization issues")
            suggestions.append("Look for information disclosure")
        
        if hasattr(result, 'parameters') and len(result.parameters) > 0:
            suggestions.append("Test all parameters for injection vulnerabilities")
            suggestions.append("Check for parameter pollution")
        
        if hasattr(result, 'forms') and len(result.forms) > 0:
            suggestions.append("Test forms for CSRF")
            suggestions.append("Check input validation")
        
        return suggestions[:5]
    
    def _classify_endpoint_type(self, path: str, params: List[str]) -> str:
        path_lower = path.lower()
        
        if 'login' in path_lower or 'signin' in path_lower:
            return "Authentication"
        if 'admin' in path_lower:
            return "Administration"
        if 'api' in path_lower:
            return "API"
        if 'user' in path_lower or 'profile' in path_lower:
            return "User Data"
        if 'search' in path_lower or 'query' in path_lower:
            return "Search"
        if 'file' in path_lower or 'upload' in path_lower:
            return "File Handling"
        if any(p in params for p in ['id', 'user_id', 'item_id']):
            return "Resource Access"
        
        return "General"
