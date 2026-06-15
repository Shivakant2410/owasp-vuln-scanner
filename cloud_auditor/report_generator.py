"""
Report Generator — Multi-Format Security Report Export
======================================================

Generates professional security audit reports in JSON and HTML formats.
The HTML report features a dark cybersecurity theme with interactive
severity filtering and executive summary.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional

from cloud_auditor.findings import FindingSet, Severity


class ReportGenerator:
    """Generates audit reports in multiple output formats.

    Attributes:
        findings: The FindingSet containing all audit results.
        compliance: Optional compliance score data.
    """

    def __init__(
        self,
        findings: FindingSet,
        compliance: Optional[dict] = None,
    ) -> None:
        self.findings = findings
        self.compliance = compliance

    def export_json(self, filepath: str) -> str:
        """Export findings as a JSON file.

        Args:
            filepath: Destination file path.

        Returns:
            The absolute path to the exported file.
        """
        data = self.findings.to_dict()

        if self.compliance:
            data["compliance"] = self.compliance

        abs_path = os.path.abspath(filepath)
        with open(abs_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        return abs_path

    def export_html(self, filepath: str) -> str:
        """Export findings as a dark-themed HTML report.

        Args:
            filepath: Destination file path.

        Returns:
            The absolute path to the exported file.
        """
        html = self._generate_html_report()

        abs_path = os.path.abspath(filepath)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(html)

        return abs_path

    def _generate_html_report(self) -> str:
        """Generate the full HTML report with embedded CSS and JS.

        Returns:
            Complete HTML document as a string.
        """
        findings = self.findings
        risk_score = findings.risk_score
        counts = findings.severity_counts
        sorted_findings = findings.sorted_by_severity()

        # Determine risk level label
        if risk_score >= 80:
            risk_label = "CRITICAL"
            risk_color = "#ff4444"
        elif risk_score >= 60:
            risk_label = "HIGH"
            risk_color = "#ff6b6b"
        elif risk_score >= 40:
            risk_label = "MEDIUM"
            risk_color = "#ffd93d"
        elif risk_score >= 20:
            risk_label = "LOW"
            risk_color = "#6bcbff"
        else:
            risk_label = "MINIMAL"
            risk_color = "#4caf50"

        # Build findings rows
        findings_rows = ""
        for i, f in enumerate(sorted_findings):
            sev_color = f.severity.html_color
            findings_rows += f"""
            <tr class="finding-row" data-severity="{f.severity.value}" data-service="{f.service.lower()}">
                <td><span class="severity-badge" style="background:{sev_color}">{f.severity.value}</span></td>
                <td>{f.service}</td>
                <td>{self._esc(f.title)}</td>
                <td>{self._esc(f.resource)}</td>
                <td>{self._esc(f.region or 'N/A')}</td>
                <td>{self._esc(f.remediation)}</td>
                <td>{', '.join(f.compliance) if f.compliance else '—'}</td>
            </tr>"""

        # Build service breakdown
        services: dict[str, int] = {}
        for f in sorted_findings:
            services[f.service] = services.get(f.service, 0) + 1

        service_bars = ""
        for svc, count in sorted(services.items(), key=lambda x: -x[1]):
            max_count = max(services.values()) if services else 1
            width_pct = (count / max_count) * 100
            service_bars += f"""
            <div class="service-bar-row">
                <span class="service-label">{svc}</span>
                <div class="service-bar-track">
                    <div class="service-bar-fill" style="width:{width_pct}%"></div>
                </div>
                <span class="service-count">{count}</span>
            </div>"""

        # Build compliance section
        compliance_html = ""
        if self.compliance:
            score = self.compliance.get("score_percentage", 0)
            controls = self.compliance.get("controls", {})
            failed = self.compliance.get("failed", 0)
            passed = self.compliance.get("passed", 0)

            controls_rows = ""
            for ctrl_id, ctrl_data in sorted(controls.items()):
                status = ctrl_data["status"]
                status_class = "pass" if status == "PASS" else "fail"
                status_icon = "✓" if status == "PASS" else "✗"
                controls_rows += f"""
                <tr>
                    <td>{ctrl_id}</td>
                    <td>{self._esc(ctrl_data['description'])}</td>
                    <td class="{status_class}">{status_icon} {status}</td>
                </tr>"""

            compliance_html = f"""
            <section class="section">
                <h2>⚖️ CIS Compliance Score: {score}%</h2>
                <p>{passed} passed / {failed} failed / {len(controls)} total controls</p>
                <div class="compliance-bar-track">
                    <div class="compliance-bar-fill" style="width:{score}%"></div>
                </div>
                <table class="compliance-table">
                    <thead>
                        <tr><th>Control</th><th>Description</th><th>Status</th></tr>
                    </thead>
                    <tbody>{controls_rows}</tbody>
                </table>
            </section>"""

        # Get unique services for filter buttons
        unique_services = sorted(set(f.service for f in sorted_findings))
        service_buttons = ""
        for svc in unique_services:
            service_buttons += f'<button class="filter-btn" data-service="{svc.lower()}">{svc}</button>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Security Audit Report</title>
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #1a2332;
            --text-primary: #e0e6ed;
            --text-secondary: #8b95a5;
            --accent: #3b82f6;
            --border: #1e293b;
            --critical: #ff4444;
            --high: #ff6b6b;
            --medium: #ffd93d;
            --low: #6bcbff;
            --info: #aaaaaa;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}
        .header {{
            text-align: center;
            padding: 2rem 0 3rem;
            border-bottom: 1px solid var(--border);
        }}
        .header h1 {{
            font-size: 2rem;
            color: var(--accent);
            margin-bottom: 0.5rem;
        }}
        .header p {{ color: var(--text-secondary); }}
        .risk-score {{
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 2rem;
            margin: 2rem 0;
            flex-wrap: wrap;
        }}
        .risk-gauge {{
            width: 180px;
            height: 180px;
            border-radius: 50%;
            border: 8px solid {risk_color};
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            background: var(--bg-card);
        }}
        .risk-gauge .score {{ font-size: 3rem; font-weight: bold; color: {risk_color}; }}
        .risk-gauge .label {{ font-size: 0.9rem; color: var(--text-secondary); }}
        .severity-cards {{
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            justify-content: center;
        }}
        .sev-card {{
            padding: 1rem 1.5rem;
            border-radius: 8px;
            background: var(--bg-card);
            border-left: 4px solid;
            min-width: 120px;
            text-align: center;
        }}
        .sev-card.critical {{ border-color: var(--critical); }}
        .sev-card.high {{ border-color: var(--high); }}
        .sev-card.medium {{ border-color: var(--medium); }}
        .sev-card.low {{ border-color: var(--low); }}
        .sev-card.info {{ border-color: var(--info); }}
        .sev-card .count {{ font-size: 2rem; font-weight: bold; }}
        .sev-card .label {{ font-size: 0.8rem; color: var(--text-secondary); }}
        .section {{
            margin: 2rem 0;
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--border);
        }}
        .section h2 {{
            font-size: 1.3rem;
            margin-bottom: 1rem;
            color: var(--text-primary);
        }}
        .service-bar-row {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin: 0.5rem 0;
        }}
        .service-label {{ width: 80px; text-align: right; color: var(--text-secondary); font-size: 0.85rem; }}
        .service-bar-track {{
            flex: 1;
            height: 20px;
            background: var(--bg-primary);
            border-radius: 4px;
            overflow: hidden;
        }}
        .service-bar-fill {{ height: 100%; background: var(--accent); border-radius: 4px; transition: width 0.5s; }}
        .service-count {{ width: 30px; color: var(--text-secondary); font-size: 0.85rem; }}
        .filter-bar {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-bottom: 1rem;
            align-items: center;
        }}
        .filter-btn {{
            padding: 0.3rem 0.8rem;
            border: 1px solid var(--border);
            background: var(--bg-secondary);
            color: var(--text-secondary);
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8rem;
            transition: all 0.2s;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background: var(--accent);
            color: white;
            border-color: var(--accent);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }}
        th {{
            text-align: left;
            padding: 0.75rem;
            background: var(--bg-primary);
            color: var(--text-secondary);
            font-weight: 600;
            border-bottom: 2px solid var(--border);
        }}
        td {{
            padding: 0.75rem;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}
        tr:hover {{ background: rgba(59, 130, 246, 0.05); }}
        .severity-badge {{
            display: inline-block;
            padding: 0.15rem 0.5rem;
            border-radius: 3px;
            color: #000;
            font-weight: bold;
            font-size: 0.75rem;
        }}
        .compliance-bar-track {{
            height: 24px;
            background: var(--bg-primary);
            border-radius: 4px;
            overflow: hidden;
            margin: 1rem 0;
        }}
        .compliance-bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, #4caf50, #66bb6a);
            border-radius: 4px;
            transition: width 0.5s;
        }}
        .pass {{ color: #4caf50; font-weight: bold; }}
        .fail {{ color: #ff4444; font-weight: bold; }}
        .compliance-table {{ margin-top: 1rem; }}
        .footer {{
            text-align: center;
            padding: 2rem 0;
            color: var(--text-secondary);
            font-size: 0.8rem;
            border-top: 1px solid var(--border);
            margin-top: 3rem;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>☁️ Cloud Security Audit Report</h1>
        <p>Account: {self._esc(findings.account_id or 'N/A')} | 
           Target: {self._esc(findings.scan_target or 'N/A')} | 
           Timestamp: {self._esc(findings.scan_timestamp or 'N/A')}</p>
    </div>

    <div class="risk-score">
        <div class="risk-gauge">
            <span class="score">{risk_score}</span>
            <span class="label">Risk Score /100</span>
        </div>
        <div class="severity-cards">
            <div class="sev-card critical">
                <div class="count">{counts.get('CRITICAL', 0)}</div>
                <div class="label">CRITICAL</div>
            </div>
            <div class="sev-card high">
                <div class="count">{counts.get('HIGH', 0)}</div>
                <div class="label">HIGH</div>
            </div>
            <div class="sev-card medium">
                <div class="count">{counts.get('MEDIUM', 0)}</div>
                <div class="label">MEDIUM</div>
            </div>
            <div class="sev-card low">
                <div class="count">{counts.get('LOW', 0)}</div>
                <div class="label">LOW</div>
            </div>
            <div class="sev-card info">
                <div class="count">{counts.get('INFO', 0)}</div>
                <div class="label">INFO</div>
            </div>
        </div>
    </div>

    <section class="section">
        <h2>📊 Findings by Service</h2>
        {service_bars}
    </section>

    {compliance_html}

    <section class="section">
        <h2>🔍 All Findings ({findings.total} total)</h2>
        <div class="filter-bar">
            <button class="filter-btn active" data-service="all">All</button>
            {service_buttons}
            <span style="margin-left:auto;color:var(--text-secondary);font-size:0.8rem">
                Click to filter by service
            </span>
        </div>
        <div style="overflow-x:auto">
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Service</th>
                        <th>Finding</th>
                        <th>Resource</th>
                        <th>Region</th>
                        <th>Remediation</th>
                        <th>Compliance</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
        </div>
    </section>

    <div class="footer">
        <p>Cloud Security Auditor v1.2.0 | Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
        <p>For authorized security assessment use only.</p>
    </div>

    <script>
        document.querySelectorAll('.filter-btn').forEach(btn => {{
            btn.addEventListener('click', () => {{
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                const service = btn.dataset.service;
                document.querySelectorAll('.finding-row').forEach(row => {{
                    if (service === 'all' || row.dataset.service === service) {{
                        row.style.display = '';
                    }} else {{
                        row.style.display = 'none';
                    }}
                }});
            }});
        }});
    </script>
</body>
</html>"""

        return html

    @staticmethod
    def _esc(text: str) -> str:
        """Escape HTML special characters.

        Args:
            text: Raw text string.

        Returns:
            HTML-escaped string.
        """
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )
