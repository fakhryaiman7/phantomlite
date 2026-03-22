"""
PhantomLite Scoring System Module
Scores targets based on various attributes for prioritization.
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ScoredTarget:
    url: str
    score: int
    category: str
    reasons: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class Scorer:
    SCORES = {
        'login_form': 30,
        'input_field': 20,
        'multiple_params': 40,
        'sensitive_path': 50,
        'admin_panel': 45,
        'api_endpoint': 40,
        'file_upload': 55,
        'password_field': 50,
        'csrf_missing': 25,
        'tech_stack': 20,
        'interesting_status': 15,
        'redirect_param': 30,
        'id_param': 35,
        'sqli_indicator': 60,
        'xss_indicator': 45,
        'open_redirect': 40,
        'auth_bypass': 70,
        'idor': 50,
        'ssrf': 55,
        'lfi': 60,
        'rce': 80,
    }
    
    def __init__(self, logger=None):
        self.logger = logger
        self.targets: List[ScoredTarget] = []
    
    def score_target(
        self,
        url: str,
        has_login_form: bool = False,
        input_count: int = 0,
        param_count: int = 0,
        is_sensitive_path: bool = False,
        has_password_field: bool = False,
        tech_stack: List[str] = None,
        status_code: int = 200,
        params: List[str] = None,
        vuln_findings: List = None
    ) -> ScoredTarget:
        score = 0
        reasons = []
        metadata = {}
        
        if has_login_form:
            score += self.SCORES['login_form']
            reasons.append("Login form detected")
        
        if input_count > 0:
            score += min(input_count * 5, self.SCORES['input_field'])
            reasons.append(f"{input_count} input fields")
        
        if param_count >= 3:
            score += self.SCORES['multiple_params']
            reasons.append(f"Multiple parameters ({param_count})")
        
        if is_sensitive_path:
            score += self.SCORES['sensitive_path']
            reasons.append("Sensitive path")
        
        if has_password_field:
            score += self.SCORES['password_field']
            reasons.append("Password field")
        
        if tech_stack:
            for tech in tech_stack:
                if tech.lower() in ['wordpress', 'drupal', 'joomla']:
                    score += self.SCORES['tech_stack']
                    reasons.append(f"Known CMS: {tech}")
                    break
        
        if status_code == 200:
            score += self.SCORES['interesting_status']
        
        if params:
            if any(p in ['redirect', 'url', 'next'] for p in params):
                score += self.SCORES['redirect_param']
                reasons.append("Redirect parameter")
            
            if any(p in ['id', 'user_id', 'item_id'] for p in params):
                score += self.SCORES['id_param']
                reasons.append("ID parameter (IDOR potential)")
        
        category = self._categorize(score, reasons)
        
        metadata = {
            'input_count': input_count,
            'param_count': param_count,
            'status_code': status_code,
            'tech_stack': tech_stack or []
        }
        
        target = ScoredTarget(
            url=url,
            score=score,
            category=category,
            reasons=reasons,
            metadata=metadata
        )
        
        self.targets.append(target)
        return target
    
    def score_from_analysis(self, analysis_results: List) -> List[ScoredTarget]:
        scored = []
        
        for result in analysis_results:
            if hasattr(result, 'score') and hasattr(result, 'target'):
                details = result.details if hasattr(result, 'details') else {}
                
                target = ScoredTarget(
                    url=result.target,
                    score=result.score,
                    category=result.target_type if hasattr(result, 'target_type') else 'Unknown',
                    reasons=result.suggestions if hasattr(result, 'suggestions') else [],
                    metadata=details
                )
                scored.append(target)
        
        scored.sort(key=lambda x: x.score, reverse=True)
        return scored
    
    def score_vuln_findings(self, findings: List) -> List[ScoredTarget]:
        scored = []
        
        severity_multipliers = {
            'high': 1.5,
            'medium': 1.0,
            'low': 0.5
        }
        
        for finding in findings:
            base_score = 50
            
            if hasattr(finding, 'severity'):
                multiplier = severity_multipliers.get(finding.severity, 1.0)
                score = int(base_score * multiplier)
            else:
                score = base_score
            
            vuln_type = finding.vuln_type if hasattr(finding, 'vuln_type') else 'Unknown'
            
            target = ScoredTarget(
                url=finding.url if hasattr(finding, 'url') else 'Unknown',
                score=score,
                category=vuln_type,
                reasons=[finding.recommendation if hasattr(finding, 'recommendation') else ''],
                metadata={
                    'severity': finding.severity if hasattr(finding, 'severity') else 'unknown',
                    'finding': str(finding)
                }
            )
            scored.append(target)
        
        scored.sort(key=lambda x: x.score, reverse=True)
        return scored
    
    def get_high_value_targets(
        self,
        threshold: int = 40
    ) -> List[ScoredTarget]:
        return [t for t in self.targets if t.score >= threshold]
    
    def get_top_targets(
        self,
        count: int = 10
    ) -> List[ScoredTarget]:
        sorted_targets = sorted(self.targets, key=lambda x: x.score, reverse=True)
        return sorted_targets[:count]
    
    def get_by_category(self, category: str) -> List[ScoredTarget]:
        return [t for t in self.targets if t.category.lower() == category.lower()]
    
    def _categorize(self, score: int, reasons: List[str]) -> str:
        if score >= 70:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 30:
            return "Medium"
        else:
            return "Low"
    
    def generate_summary(self) -> Dict[str, Any]:
        categories = {}
        for target in self.targets:
            cat = target.category
            if cat not in categories:
                categories[cat] = {'count': 0, 'total_score': 0}
            categories[cat]['count'] += 1
            categories[cat]['total_score'] += target.score
        
        return {
            'total_targets': len(self.targets),
            'categories': categories,
            'high_value_count': len(self.get_high_value_targets()),
            'average_score': sum(t.score for t in self.targets) / len(self.targets) if self.targets else 0
        }
