"""
PhantomLite Interactive HTML Report Generator
Generates a professional dashboard for recon results.
"""
import os
import json
from datetime import datetime
from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhantomLite Report - {{ domain }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        :root {
            --bg-dark: #0f172a;
            --card-bg: #1e293b;
            --primary: #38bdf8;
            --accent: #c084fc;
        }
        body {
            background-color: var(--bg-dark);
            color: #f8fafc;
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
        }
        .sidebar {
            background-color: var(--card-bg);
            min-height: 100vh;
            border-right: 1px solid #334155;
        }
        .nav-link {
            color: #94a3b8;
            padding: 0.75rem 1.5rem;
            transition: all 0.2s;
        }
        .nav-link:hover, .nav-link.active {
            color: var(--primary);
            background-color: #334155;
        }
        .card {
            background-color: var(--card-bg);
            border: 1px solid #334155;
            color: #f8fafc;
            margin-bottom: 1.5rem;
        }
        .severity-high { border-left: 5px solid #ef4444; }
        .severity-medium { border-left: 5px solid #f59e0b; }
        .severity-low { border-left: 5px solid #10b981; }
        .badge-high { background-color: #ef4444; }
        .badge-medium { background-color: #f59e0b; }
        .badge-low { background-color: #10b981; }
        pre {
            background-color: #0f172a;
            padding: 1rem;
            border-radius: 0.5rem;
            border: 1px solid #334155;
            color: #38bdf8;
            font-size: 0.875rem;
        }
        h1, h2, h3 { color: var(--primary); font-weight: 700; }
        .stat-card {
            text-align: center;
            padding: 1.5rem;
        }
        .stat-value {
            font-size: 2rem;
            font-weight: 800;
            margin-bottom: 0;
            color: var(--accent);
        }
        .stat-label {
            color: #94a3b8;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <nav class="col-md-2 d-none d-md-block sidebar py-4">
                <div class="px-4 mb-4">
                    <h3 class="h5 mb-0"><i class="bi bi-ghost me-2"></i>PhantomLite</h3>
                    <small class="text-muted">Pro Recon v2.0</small>
                </div>
                <div class="nav flex-column nav-pills" id="v-pills-tab" role="tablist">
                    <button class="nav-link active text-start" data-bs-toggle="pill" data-bs-target="#tab-dashboard" type="button"><i class="bi bi-speedometer2 me-2"></i>Dashboard</button>
                    <button class="nav-link text-start" data-bs-toggle="pill" data-bs-target="#tab-vulns" type="button"><i class="bi bi-shield-exclamation me-2"></i>Vulnerabilities</button>
                    <button class="nav-link text-start" data-bs-toggle="pill" data-bs-target="#tab-subdomains" type="button"><i class="bi bi-diagram-3 me-2"></i>Subdomains</button>
                    <button class="nav-link text-start" data-bs-toggle="pill" data-bs-target="#tab-endpoints" type="button"><i class="bi bi-link-45deg me-2"></i>Endpoints</button>
                    <button class="nav-link text-start" data-bs-toggle="pill" data-bs-target="#tab-ports" type="button"><i class="bi bi-cpu me-2"></i>Open Ports</button>
                </div>
            </nav>

            <!-- Main Content -->
            <main class="col-md-10 ms-sm-auto px-md-4 py-4">
                <div class="tab-content">
                    
                    <!-- Dashboard -->
                    <div class="tab-pane fade show active" id="tab-dashboard">
                        <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom border-secondary">
                            <h1 class="h2">Results for: {{ domain }}</h1>
                            <div class="btn-toolbar mb-2 mb-md-0 text-muted">
                                <i class="bi bi-calendar3 me-2"></i> {{ timestamp }}
                            </div>
                        </div>

                        <div class="row mb-4">
                            <div class="col-md-3">
                                <div class="card stat-card">
                                    <p class="stat-value">{{ subdomains|length }}</p>
                                    <p class="stat-label">Subdomains</p>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card stat-card">
                                    <p class="stat-value">{{ live_hosts|length }}</p>
                                    <p class="stat-label">Live Hosts</p>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card stat-card">
                                    <p class="stat-value">{{ vuln_findings|length }}</p>
                                    <p class="stat-label">Vulnerabilities</p>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card stat-card">
                                    <p class="stat-value">{{ wayback_urls|length }}</p>
                                    <p class="stat-label">Wayback URLs</p>
                                </div>
                            </div>
                        </div>

                        <div class="card p-4">
                            <h3>Welcome to PhantomLite Pro</h3>
                            <p class="text-muted">Reconnaissance scan completed successfully. Navigate through the tabs to explore deep findings.</p>
                            <hr class="border-secondary">
                            <div class="row">
                                <div class="col-md-6">
                                    <h5>Scan Summary</h5>
                                    <table class="table table-dark table-striped mt-3">
                                        <tr><td>Domain</td><td>{{ domain }}</td></tr>
                                        <tr><td>Total Targets</td><td>{{ scored_targets|length }}</td></tr>
                                        <tr><td>Exposed Ports</td><td>{{ open_ports|length }} hosts</td></tr>
                                        <tr><td>JS Files Found</td><td>{{ js_endpoints|length }}</td></tr>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Vulnerabilities -->
                    <div class="tab-pane fade" id="tab-vulns">
                        <h2 class="mb-4">Vulnerability Findings</h2>
                        {% if vuln_findings %}
                            {% for vuln in vuln_findings %}
                            <div class="card severity-{{ vuln.severity }}">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between align-items-start">
                                        <h5 class="card-title">{{ vuln.type }}</h5>
                                        <span class="badge badge-{{ vuln.severity }}">{{ vuln.severity|upper }}</span>
                                    </div>
                                    <p class="text-primary mb-2"><strong>URL:</strong> {{ vuln.url }}</p>
                                    <p><strong>Description:</strong> {{ vuln.description }}</p>
                                    {% if vuln.parameter %}
                                    <p><strong>Parameter:</strong> <span class="badge bg-secondary">{{ vuln.parameter }}</span></p>
                                    {% endif %}
                                    {% if vuln.evidence %}
                                    <div class="mt-2">
                                        <strong>Evidence:</strong>
                                        <pre>{{ vuln.evidence }}</pre>
                                    </div>
                                    {% endif %}
                                    <div class="mt-3 text-info">
                                        <i class="bi bi-info-circle me-1"></i> Recommendation: {{ vuln.recommendation }}
                                    </div>
                                </div>
                            </div>
                            {% endfor %}
                        {% else %}
                            <div class="alert alert-info">No vulnerabilities found yet. Keep digging!</div>
                        {% endif %}
                    </div>

                    <!-- Subdomains -->
                    <div class="tab-pane fade" id="tab-subdomains">
                        <h2 class="mb-4">Discovered Subdomains</h2>
                        <div class="card">
                            <ul class="list-group list-group-flush">
                                {% for sub in subdomains %}
                                <li class="list-group-item bg-transparent text-light border-0 py-1">{{ sub }}</li>
                                {% endfor %}
                            </ul>
                        </div>
                    </div>

                    <!-- Endpoints -->
                    <div class="tab-pane fade" id="tab-endpoints">
                        <h2 class="mb-4">Web Endpoints & Parameters</h2>
                        <div class="card overflow-auto">
                            <table class="table table-dark table-hover mb-0">
                                <thead>
                                    <tr>
                                        <th>Method</th>
                                        <th>URL</th>
                                        <th>Parameters</th>
                                        <th>Source</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for ep in endpoints %}
                                    <tr>
                                        <td><span class="badge bg-info">{{ ep.method }}</span></td>
                                        <td class="text-break">{{ ep.url }}</td>
                                        <td>
                                            {% for param in ep.params %}
                                            <span class="badge bg-secondary">{{ param }}</span>
                                            {% endfor %}
                                        </td>
                                        <td>{{ ep.source }}</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Open Ports -->
                    <div class="tab-pane fade" id="tab-ports">
                        <h2 class="mb-4">Open Ports & Services</h2>
                        {% for host, ports in open_ports.items() %}
                        <div class="card p-3 mb-3">
                            <h5 class="text-accent mb-3"><i class="bi bi-server me-2"></i> {{ host }}</h5>
                            <table class="table table-dark table-sm">
                                <thead>
                                    <tr>
                                        <th>Port</th>
                                        <th>Service</th>
                                        <th>State</th>
                                        <th>Banner</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for p in ports %}
                                    <tr>
                                        <td>{{ p.port }}</td>
                                        <td>{{ p.service }}</td>
                                        <td>{{ p.state }}</td>
                                        <td class="text-muted">{{ p.banner }}</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                        {% endfor %}
                    </div>

                </div>
            </main>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

def generate_html_report(data: dict, output_path: str):
    template = Template(HTML_TEMPLATE)
    html_content = template.render(**data)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_path
