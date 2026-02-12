"""Professional HTML report generation"""
from jinja2 import Template
from datetime import datetime
from pathlib import Path
from typing import Dict, List
import json

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Sentinel Security Audit Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .risk-critical { color: #dc3545; font-weight: bold; }
        .risk-high { color: #fd7e14; font-weight: bold; }
        .risk-medium { color: #ffc107; font-weight: bold; }
        .risk-low { color: #17a2b8; }
        .card { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .finding { border-left: 4px solid; padding-left: 15px; margin-bottom: 15px; }
        .finding.critical { border-color: #dc3545; background: #fff5f5; }
        .finding.high { border-color: #fd7e14; background: #fff9f5; }
        .finding.medium { border-color: #ffc107; background: #fffdf5; }
        .finding.low { border-color: #17a2b8; background: #f5faff; }
        .code { background: #f4f4f4; padding: 10px; border-radius: 4px; font-family: 'Courier New', monospace; overflow-x: auto; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .metric { text-align: center; padding: 20px; background: white; border-radius: 8px; }
        .metric-value { font-size: 2em; font-weight: bold; color: #333; }
        .metric-label { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Sentinel Security Audit</h1>
        <p>Target: {{ target }}<br>
        Chain: {{ chain }}<br>
        Timestamp: {{ timestamp }}<br>
        Risk Score: <span class="risk-{{ risk_rating|lower }}">{{ risk_score }}/100 ({{ risk_rating }})</span></p>
    </div>

    <div class="card">
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="metric">
                <div class="metric-value" style="color: #dc3545;">{{ summary.severity_breakdown.Critical or 0 }}</div>
                <div class="metric-label">Critical</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: #fd7e14;">{{ summary.severity_breakdown.High or 0 }}</div>
                <div class="metric-label">High</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: #ffc107;">{{ summary.severity_breakdown.Medium or 0 }}</div>
                <div class="metric-label">Medium</div>
            </div>
            <div class="metric">
                <div class="metric-value">{{ summary.total_findings }}</div>
                <div class="metric-label">Total Findings</div>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>Detailed Findings</h2>
        {% for finding in findings %}
        <div class="finding {{ finding.severity|lower }}">
            <h3>[{{ finding.severity }}] {{ finding.title }}</h3>
            <p><strong>Category:</strong> {{ finding.category }} | <strong>Confidence:</strong> {{ finding.confidence }} | <strong>Tool:</strong> {{ finding.tool }}</p>
            <p>{{ finding.description }}</p>
            {% if finding.file %}
            <div class="code">File: {{ finding.file }}:{{ finding.line }}</div>
            {% endif %}
            {% if finding.proof_of_concept %}
            <div class="code"><strong>Proof of Concept:</strong><br>{{ finding.proof_of_concept }}</div>
            {% endif %}
            {% if finding.remediation %}
            <div style="background: #e8f5e9; padding: 10px; border-radius: 4px; margin-top: 10px;">
                <strong>Remediation:</strong> {{ finding.remediation }}
            </div>
            {% endif %}
        </div>
        {% endfor %}
    </div>

    <div class="card">
        <h2>Technical Details</h2>
        <p><strong>Compiler Version:</strong> {{ contract_info.compiler or 'Unknown' }}</p>
        <p><strong>Contract Type:</strong> {{ contract_info.contract_type or 'Standard' }}</p>
        {% if contract_info.is_proxy %}
        <p><strong>Proxy Pattern:</strong> Yes (Implementation: {{ contract_info.implementation }})</p>
        {% endif %}
    </div>
</body>
</html>
"""

class HTMLReporter:
    def generate(self, results: Dict, output_path: str):
        """Generate professional HTML report"""
        template = Template(HTML_TEMPLATE)
        
        html_content = template.render(
            target=results["scan_metadata"]["target"],
            chain=results["scan_metadata"]["chain"],
            timestamp=datetime.fromtimestamp(results["scan_metadata"]["timestamp"]).isoformat(),
            risk_score=results["risk_score"],
            risk_rating=results["summary"]["risk_rating"],
            summary=results["summary"],
            findings=results["findings"],
            contract_info=results["contract_info"]
        )
        
        with open(output_path, 'w') as f:
            f.write(html_content)
            
        print(f"[+] HTML Report generated: {output_path}")
