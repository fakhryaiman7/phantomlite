"""
PhantomLite Advanced Scoring System Module
Scores targets based on vulnerability potential and attack surface.
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ScoredTarget:
    url: str
    score: int
    category: str
    priority: str = "medium"
    reasons: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AdvancedScorer:
    SCORES = {
        'has_parameters': 40,
        'api_endpoint': 50,
        'login_form': 70,
        'file_upload': 90,
        'sensitive_keyword': 30,
        'password_field': 50,
        'csrf_missing': 25,
        'tech_stack': 20,
        'interesting_status': 15,
        'redirect_param': 30,
        'id_param': 35,
        'sqli_indicator': 60,
        'xss_indicator': 45,
        'open_redirect': 40,
        'idor_param': 40,
        'ssrf_param': 50,
        'lfi_param': 55,
        'ssti_param': 60,
        'auth_bypass': 70,
        'idor': 50,
        'ssrf': 55,
        'lfi': 60,
        'rce': 80,
    }
    
    PRIORITY_THRESHOLDS = {
        'critical': 80,
        'high': 60,
        'medium': 40,
        'low': 20
    }
    
    def __init__(self, logger=None):
        self.logger = logger
        self.targets: List[ScoredTarget] = []
    
    def score_endpoint(self, endpoint: Dict) -> ScoredTarget:
        score = 0
        reasons = []
        metadata = {}
        
        path = endpoint.get('path', '')
        params = endpoint.get('params', [])
        method = endpoint.get('method', 'GET')
        is_sensitive = endpoint.get('is_sensitive', False)
        has_params = endpoint.get('has_params', len(params) > 0)
        
        if has_params and params:
            score += self.SCORES['has_parameters']
            reasons.append(f"Has {len(params)} parameter(s)")
            metadata['param_count'] = len(params)
        
        path_lower = path.lower()
        
        if any(kw in path_lower for kw in ['/api/', '/v1/', '/v2/', '/graphql', '/rest/']):
            score += self.SCORES['api_endpoint']
            reasons.append("API endpoint")
        
        if any(kw in path_lower for kw in ['login', 'signin', 'auth', 'authenticate']):
            score += self.SCORES['login_form']
            reasons.append("Login/authentication endpoint")
        
        if any(kw in path_lower for kw in ['upload', 'file', 'attachment', 'media']):
            score += self.SCORES['file_upload']
            reasons.append("File upload functionality")
        
        if any(kw in path_lower for kw in ['admin', 'dashboard', 'manage', 'panel', 'console']):
            score += self.SCORES['sensitive_keyword']
            reasons.append("Admin/management endpoint")
        
        if any(kw in path_lower for kw in ['debug', 'test', 'dev', 'staging', 'internal']):
            score += self.SCORES['sensitive_keyword']
            reasons.append("Development/testing endpoint")
        
        params_lower = [p.lower() for p in params]
        
        idor_params = ['id', 'user_id', 'post_id', 'item_id', 'product_id', 'uid', 'pid']
        if any(p in params_lower for p in idor_params):
            score += self.SCORES['idor_param']
            reasons.append("ID parameter (IDOR potential)")
        
        xss_params = ['q', 'query', 'search', 'term', 'comment', 'message', 'content', 'name', 'title']
        if any(p in params_lower for p in xss_params):
            score += self.SCORES['xss_indicator']
            reasons.append("XSS-susceptible parameter")
        
        ssrf_params = ['url', 'uri', 'src', 'dest', 'redirect', 'callback', 'host']
        if any(p in params_lower for p in ssrf_params):
            score += self.SCORES['ssrf_param']
            reasons.append("SSRF-susceptible parameter")
        
        lfi_params = ['file', 'path', 'include', 'require', 'load', 'template', 'doc']
        if any(p in params_lower for p in lfi_params):
            score += self.SCORES['lfi_param']
            reasons.append("LFI-susceptible parameter")
        
        redirect_params = ['redirect', 'url', 'next', 'return', 'callback', 'goto', 'destination']
        if any(p in params_lower for p in redirect_params):
            score += self.SCORES['redirect_param']
            reasons.append("Redirect parameter")
        
        if is_sensitive:
            score += self.SCORES['sensitive_keyword']
            reasons.append("Sensitive path")
        
        if method == 'POST':
            score += 10
            reasons.append("POST method")
        
        priority = self._determine_priority(score)
        
        return ScoredTarget(
            url=endpoint.get('url', path),
            score=score,
            category=self._categorize(score),
            priority=priority,
            reasons=reasons,
            metadata=metadata
        )
    
    def score_form(self, form: Dict) -> ScoredTarget:
        score = 0
        reasons = []
        metadata = {}
        
        inputs = form.get('inputs', [])
        method = form.get('method', 'GET').upper()
        
        input_names = [inp.get('name', '').lower() for inp in inputs]
        input_types = [inp.get('type', 'text').lower() for inp in inputs]
        
        has_password = any(t == 'password' for t in input_types)
        has_file = any(t == 'file' for t in input_types)
        has_email = any('email' in name for name in input_names)
        
        csrf_safe = any('csrf' in name or 'token' in name for name in input_names)
        
        if has_password:
            score += self.SCORES['password_field']
            reasons.append("Password field detected")
        
        if has_file:
            score += self.SCORES['file_upload']
            reasons.append("File upload field detected")
        
        if has_email:
            score += 15
            reasons.append("Email field detected")
        
        if not csrf_safe:
            score += self.SCORES['csrf_missing']
            reasons.append("No CSRF protection")
        
        if len(inputs) > 5:
            score += 20
            reasons.append(f"Multiple inputs ({len(inputs)})")
        
        priority = self._determine_priority(score)
        
        return ScoredTarget(
            url=form.get('action', ''),
            score=score,
            category=self._categorize(score),
            priority=priority,
            reasons=reasons,
            metadata={'method': method, 'input_count': len(inputs)}
        )
    
    def score_vuln(self, finding) -> ScoredTarget:
        vuln_type = getattr(finding, 'vuln_type', 'Unknown')
        severity = getattr(finding, 'severity', 'low')
        url = getattr(finding, 'url', '')
        param = getattr(finding, 'parameter', '')
        
        severity_multipliers = {
            'critical': 1.5,
            'high': 1.3,
            'medium': 1.0,
            'low': 0.7
        }
        
        base_scores = {
            'SQL Injection': 80,
            'SQL Injection Indicator': 60,
            'XSS': 70,
            'Reflected XSS': 60,
            'Stored XSS': 80,
            'Open Redirect': 40,
            'SSRF': 70,
            'IDOR': 75,
            'LFI': 65,
            'RCE': 95,
            'CSRF': 45,
            'SSTI': 80,
            'Missing Security Header': 20,
            'Weak CSP': 30,
            'Information Disclosure': 25,
        }
        
        base_score = base_scores.get(vuln_type, 50)
        multiplier = severity_multipliers.get(severity.lower(), 1.0)
        score = int(base_score * multiplier)
        
        if param:
            reasons = [f"{vuln_type} in parameter '{param}'"]
        else:
            reasons = [vuln_type]
        
        priority = self._determine_priority(score)
        
        return ScoredTarget(
            url=url,
            score=score,
            category=vuln_type,
            priority=priority,
            reasons=reasons,
            metadata={'severity': severity}
        )
    
    def add_target(self, target: ScoredTarget):
        self.targets.append(target)
    
    def add_from_endpoints(self, endpoints: List[Dict]):
        for endpoint in endpoints:
            scored = self.score_endpoint(endpoint)
            self.targets.append(scored)
    
    def add_from_forms(self, forms: List[Dict]):
        for form in forms:
            scored = self.score_form(form)
            self.targets.append(scored)
    
    def add_from_findings(self, findings: List):
        for finding in findings:
            scored = self.score_vuln(finding)
            self.targets.append(scored)
    
    def get_all(self) -> List[ScoredTarget]:
        return sorted(self.targets, key=lambda x: x.score, reverse=True)
    
    def get_by_priority(self, priority: str) -> List[ScoredTarget]:
        return sorted(
            [t for t in self.targets if t.priority == priority],
            key=lambda x: x.score,
            reverse=True
        )
    
    def get_high_value(self, threshold: int = 50) -> List[ScoredTarget]:
        return sorted(
            [t for t in self.targets if t.score >= threshold],
            key=lambda x: x.score,
            reverse=True
        )
    
    def get_by_category(self, category: str) -> List[ScoredTarget]:
        return [t for t in self.targets if category.lower() in t.category.lower()]
    
    def _determine_priority(self, score: int) -> str:
        if score >= self.PRIORITY_THRESHOLDS['critical']:
            return 'critical'
        elif score >= self.PRIORITY_THRESHOLDS['high']:
            return 'high'
        elif score >= self.PRIORITY_THRESHOLDS['medium']:
            return 'medium'
        else:
            return 'low'
    
    def _categorize(self, score: int) -> str:
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        else:
            return "Low"
    
    def generate_summary(self) -> Dict[str, Any]:
        by_priority = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for target in self.targets:
            by_priority[target.priority].append(target)
        
        return {
            'total_targets': len(self.targets),
            'by_priority': {
                p: len(targets) for p, targets in by_priority.items()
            },
            'high_value_count': len(self.get_high_value()),
            'by_category': self._count_by_category(),
            'average_score': sum(t.score for t in self.targets) / len(self.targets) if self.targets else 0
        }
    
    def _count_by_category(self) -> Dict[str, int]:
        counts = {}
        for target in self.targets:
            cat = target.category
            counts[cat] = counts.get(cat, 0) + 1
        return counts


class Scorer(AdvancedScorer):
    pass
