"""Security report generator — produces HTML and optionally PDF reports."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from jinja2 import Environment, BaseLoader

from ..shared.config import get_settings
from ..shared.logging import get_logger
from ..shared.models import Dependency, ReportRequest, Secret, Severity, Vulnerability

logger = get_logger("report_generator")

_SEVERITY_COLOR: dict[str, str] = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
    "info": "#6b7280",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{{ title }}</title>
<style>
  :root { --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #e2e8f0; --muted: #94a3b8; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }
  h1 { font-size: 2rem; color: #f97316; border-bottom: 2px solid #f97316; padding-bottom: .75rem; margin-bottom: 1.5rem; }
  h2 { font-size: 1.25rem; color: #fb923c; margin: 2rem 0 .75rem; }
  .meta { color: var(--muted); font-size: .875rem; margin-bottom: 2rem; }
  .summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: .5rem; padding: 1rem 1.5rem; min-width: 120px; text-align: center; }
  .stat-card .value { font-size: 2rem; font-weight: 700; }
  .stat-card .label { font-size: .75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
  .critical { color: #ef4444; } .high { color: #f97316; } .medium { color: #eab308; } .low { color: #22c55e; } .info { color: #6b7280; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 1.5rem; }
  th { background: var(--surface); text-align: left; padding: .75rem 1rem; font-size: .75rem; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); border-bottom: 1px solid var(--border); }
  td { padding: .75rem 1rem; border-bottom: 1px solid var(--border); font-size: .875rem; vertical-align: top; }
  tr:hover td { background: rgba(255,255,255,.03); }
  .badge { display: inline-block; padding: .125rem .5rem; border-radius: 9999px; font-size: .7rem; font-weight: 600; text-transform: uppercase; }
  code { background: #0f172a; border: 1px solid var(--border); border-radius: .25rem; padding: .125rem .375rem; font-size: .8rem; color: #a5f3fc; }
  pre { background: #0f172a; border: 1px solid var(--border); border-radius: .375rem; padding: .75rem; overflow-x: auto; font-size: .8rem; color: #a5f3fc; margin: .5rem 0; }
  .footer { margin-top: 3rem; color: var(--muted); font-size: .75rem; text-align: center; }
  .pass { color: #22c55e; } .fail { color: #ef4444; }
</style>
</head>
<body>
<h1>{{ title }}</h1>
<p class="meta">Generated: {{ generated_at }} | Scan ID: {{ scan_id }}</p>

<div class="summary">
  <div class="stat-card"><div class="value critical">{{ critical_count }}</div><div class="label">Critical</div></div>
  <div class="stat-card"><div class="value high">{{ high_count }}</div><div class="label">High</div></div>
  <div class="stat-card"><div class="value medium">{{ medium_count }}</div><div class="label">Medium</div></div>
  <div class="stat-card"><div class="value low">{{ low_count }}</div><div class="label">Low</div></div>
  <div class="stat-card"><div class="value" style="color:#a855f7">{{ secrets_count }}</div><div class="label">Secrets</div></div>
  <div class="stat-card"><div class="value" style="color:#38bdf8">{{ dep_vuln_count }}</div><div class="label">Dep CVEs</div></div>
</div>

{% if vulnerabilities %}
<h2>Vulnerabilities ({{ vulnerabilities|length }})</h2>
<table>
  <thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>File / Line</th><th>CWE</th></tr></thead>
  <tbody>
  {% for v in vulnerabilities %}
  <tr>
    <td><span class="badge {{ v.severity.value }}" style="background:{{ severity_color(v.severity.value) }}20;color:{{ severity_color(v.severity.value) }}">{{ v.severity.value.upper() }}</span></td>
    <td>
      <strong>{{ v.title }}</strong><br/>
      <small style="color:var(--muted)">{{ v.description }}</small>
      {% if v.code_snippet %}<pre>{{ v.code_snippet }}</pre>{% endif %}
      {% if v.remediation %}<small><strong>Fix:</strong> {{ v.remediation }}</small>{% endif %}
    </td>
    <td>{{ v.category }}</td>
    <td>{% if v.file_path %}<code>{{ v.file_path }}</code>{% if v.line_number %} :{{ v.line_number }}{% endif %}{% else %}—{% endif %}</td>
    <td>{% if v.cwe_id %}<code>{{ v.cwe_id }}</code>{% else %}—{% endif %}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

{% if secrets %}
<h2>Detected Secrets ({{ secrets|length }})</h2>
<table>
  <thead><tr><th>Severity</th><th>Type</th><th>Masked Value</th><th>File / Line</th></tr></thead>
  <tbody>
  {% for s in secrets %}
  <tr>
    <td><span class="badge critical" style="background:#ef444420;color:#ef4444">{{ s.severity.value.upper() }}</span></td>
    <td>{{ s.type }}</td>
    <td><code>{{ s.masked_value }}</code></td>
    <td>{% if s.file_path %}<code>{{ s.file_path }}</code>{% if s.line_number %} :{{ s.line_number }}{% endif %}{% else %}—{% endif %}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

{% if dependencies %}
<h2>Dependency Risk ({{ dependencies|length }} packages)</h2>
<table>
  <thead><tr><th>Package</th><th>Version</th><th>Risk Score</th><th>CVEs</th></tr></thead>
  <tbody>
  {% for d in dependencies %}
  <tr>
    <td>{{ d.name }}</td>
    <td><code>{{ d.version }}</code></td>
    <td>
      {% if d.risk_score >= 7 %}<span class="critical">{{ "%.1f"|format(d.risk_score) }}/10</span>
      {% elif d.risk_score >= 4 %}<span class="high">{{ "%.1f"|format(d.risk_score) }}/10</span>
      {% elif d.risk_score >= 1 %}<span class="medium">{{ "%.1f"|format(d.risk_score) }}/10</span>
      {% else %}<span class="low">0.0/10</span>{% endif %}
    </td>
    <td>{% for cve in d.vulnerabilities %}<code>{{ cve.cve_id }}</code> {% endfor %}{% if not d.vulnerabilities %}—{% endif %}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

<div class="footer">
  <p>CyberShield AI &mdash; For authorized security testing only &mdash; {{ generated_at }}</p>
</div>
</body>
</html>
"""


class ReportGenerator:
    """Generate HTML security reports from scan results."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._env = Environment(loader=BaseLoader())
        self._env.globals["severity_color"] = lambda s: _SEVERITY_COLOR.get(s, "#6b7280")

    def generate_html(self, request: ReportRequest) -> str:
        """Render the HTML report and return as string."""
        vulns = request.vulnerabilities
        c = sum(1 for v in vulns if v.severity == Severity.CRITICAL)
        h = sum(1 for v in vulns if v.severity == Severity.HIGH)
        m = sum(1 for v in vulns if v.severity == Severity.MEDIUM)
        lo = sum(1 for v in vulns if v.severity == Severity.LOW)
        dep_vuln_count = sum(len(d.vulnerabilities) for d in request.dependencies)

        template = self._env.from_string(HTML_TEMPLATE)
        return template.render(
            title=request.title,
            scan_id=request.scan_id,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            vulnerabilities=vulns,
            secrets=request.secrets,
            dependencies=request.dependencies,
            critical_count=c,
            high_count=h,
            medium_count=m,
            low_count=lo,
            secrets_count=len(request.secrets),
            dep_vuln_count=dep_vuln_count,
        )

    def save_html(self, request: ReportRequest) -> str:
        """Save HTML report to disk and return file path."""
        output_dir = Path(self.settings.report_output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        file_name = f"report_{request.scan_id}.html"
        file_path = output_dir / file_name
        html_content = self.generate_html(request)
        file_path.write_text(html_content, encoding="utf-8")
        logger.info("Report saved path=%s", file_path)
        return str(file_path)

    def save_pdf(self, request: ReportRequest) -> str:
        """Save PDF report to disk (requires WeasyPrint)."""
        try:
            from weasyprint import HTML as WP_HTML
            output_dir = Path(self.settings.report_output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            file_name = f"report_{request.scan_id}.pdf"
            file_path = output_dir / file_name
            html_content = self.generate_html(request)
            WP_HTML(string=html_content).write_pdf(str(file_path))
            logger.info("PDF report saved path=%s", file_path)
            return str(file_path)
        except ImportError:
            logger.warning("WeasyPrint not available — falling back to HTML report")
            return self.save_html(request)
