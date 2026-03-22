"""
PhantomLite Helpers Module
Utility functions for common operations.
"""
import re
import hashlib
import json
from pathlib import Path
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime
import asyncio


def extract_domain(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'https://{url}')
        domain = parsed.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except Exception:
        return None


def extract_subdomains(url: str) -> Set[str]:
    try:
        parsed = urlparse(url)
        parts = parsed.netloc.split('.')
        subdomains = set()
        
        for i in range(len(parts) - 2):
            subdomains.add('.'.join(parts[i:]))
        
        return subdomains
    except Exception:
        return set()


def is_sensitive_path(path: str) -> bool:
    sensitive_keywords = [
        'admin', 'login', 'dashboard', 'wp-admin', 'administrator',
        'api', 'auth', 'config', 'backup', 'db', 'database',
        'phpMyAdmin', 'pma', 'console', 'management', 'setup',
        'install', 'wp-content', 'wp-includes', 'internal',
        'private', 'secret', 'token', 'reset', 'password',
        '.env', '.git', '.htaccess', 'config', 'server-status'
    ]
    
    path_lower = path.lower()
    return any(keyword in path_lower for keyword in sensitive_keywords)


def is_sensitive_param(param: str) -> bool:
    sensitive_params = [
        'id', 'user', 'username', 'email', 'password', 'pass',
        'token', 'key', 'secret', 'auth', 'api_key', 'apikey',
        'session', 'sessionid', 'jsessionid', 'phpsessid',
        'redirect', 'url', 'next', 'return', 'callback',
        'file', 'path', 'page', 'debug', 'test', 'admin',
        'role', 'privilege', 'permission', 'access', 'upload'
    ]
    
    param_lower = param.lower()
    return any(s in param_lower for s in sensitive_params)


def extract_params(url: str) -> List[str]:
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())
    except Exception:
        return []


def inject_param(url: str, param: str, value: str) -> str:
    try:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [value]
        new_query = urlencode(query, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
    except Exception:
        return url


def extract_links(html: str, base_url: str) -> Set[str]:
    links = set()
    
    link_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    for match in link_pattern.finditer(html):
        href = match.group(1)
        
        if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
            continue
        
        if href.startswith('/'):
            href = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}{href}"
        elif not href.startswith(('http://', 'https://')):
            href = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}/{href}"
        
        if href:
            links.add(href.split('?')[0].split('#')[0])
    
    return links


def extract_forms(html: str, base_url: str) -> List[Dict[str, Any]]:
    forms = []
    
    form_pattern = re.compile(
        r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'][^>]*>',
        re.IGNORECASE
    )
    
    input_pattern = re.compile(
        r'<input[^>]*name=["\']([^"\']*)["\'][^>]*(?:value=["\']([^"\']*)["\'])?[^>]*>',
        re.IGNORECASE
    )
    
    textarea_pattern = re.compile(
        r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>',
        re.IGNORECASE
    )
    
    select_pattern = re.compile(
        r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>',
        re.IGNORECASE
    )
    
    for form_match in form_pattern.finditer(html):
        form_action = form_match.group(1) or '/'
        form_method = form_match.group(2).upper() or 'GET'
        
        if form_action.startswith('/'):
            form_action = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}{form_action}"
        elif not form_action.startswith(('http://', 'https://')):
            form_action = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}/{form_action}"
        
        inputs = []
        for input_match in input_pattern.finditer(html, form_match.start(), form_match.end()):
            inputs.append({
                'name': input_match.group(1),
                'value': input_match.group(2) or ''
            })
        
        for textarea_match in textarea_pattern.finditer(html, form_match.start(), form_match.end()):
            inputs.append({
                'name': textarea_match.group(1),
                'value': ''
            })
        
        for select_match in select_pattern.finditer(html, form_match.start(), form_match.end()):
            inputs.append({
                'name': select_match.group(1),
                'value': ''
            })
        
        forms.append({
            'action': form_action,
            'method': form_method,
            'inputs': inputs
        })
    
    return forms


def calculate_hash(data: str) -> str:
    return hashlib.md5(data.encode()).hexdigest()


def save_cache(data: Any, cache_file: Path):
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
    except Exception:
        pass


def load_cache(cache_file: Path) -> Optional[Any]:
    try:
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return None


def is_login_form(html: str) -> bool:
    login_keywords = [
        'password', 'login', 'signin', 'sign-in', 'username',
        'email', 'remember me', 'forgot password', 'log in',
        'enter your credentials', 'authentication'
    ]
    
    html_lower = html.lower()
    matches = sum(1 for keyword in login_keywords if keyword in html_lower)
    return matches >= 2


def has_input_fields(html: str) -> bool:
    input_count = len(re.findall(r'<input[^>]*>', html, re.IGNORECASE))
    return input_count > 0


def detect_tech_stack(headers: Dict[str, str], html: str = "") -> List[str]:
    technologies = []
    
    server = headers.get('Server', '').lower()
    powered_by = headers.get('X-Powered-By', '').lower()
    headers_str = str(headers)
    
    if 'cloudflare' in str(headers):
        technologies.append('Cloudflare')
    
    if 'nginx' in server:
        technologies.append('Nginx')
    if 'apache' in server:
        technologies.append('Apache')
    if 'iis' in server:
        technologies.append('IIS')
    
    if 'php' in powered_by:
        technologies.append('PHP')
    if 'asp.net' in powered_by:
        technologies.append('ASP.NET')
    if 'express' in powered_by:
        technologies.append('Express.js')
    
    if 'wp-content' in html or 'wp-includes' in html:
        technologies.append('WordPress')
    if 'drupal' in html.lower():
        technologies.append('Drupal')
    if 'joomla' in html.lower():
        technologies.append('Joomla')
    
    if 'react' in html.lower():
        technologies.append('React')
    if 'vue' in html.lower():
        technologies.append('Vue.js')
    if 'angular' in html.lower():
        technologies.append('Angular')
    
    return list(set(technologies))


def sanitize_filename(name: str) -> str:
    return re.sub(r'[^\w\s\-\.]', '_', name)


def format_time(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    else:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"


def parse_ports(port_str: str) -> List[int]:
    ports = set()
    
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    
    return sorted(list(ports))
