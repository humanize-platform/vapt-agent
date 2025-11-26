"""
Dashboard utilities for VAPT Agent.

Provides functions to parse VAPT reports, calculate risk scores,
and generate visualizations for the dashboard.
"""

import re
from typing import Dict, List, Tuple
import plotly.graph_objects as go


def parse_vapt_report(report_md: str) -> Dict:
    """Parse VAPT report markdown to extract vulnerability data.

    Args:
        report_md: Markdown content of VAPT report

    Returns:
        Dictionary with vulnerability counts by severity and list of findings
    """
    if not report_md or "Error" in report_md[:100]:
        return {
            "severities": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "total": 0,
            "findings": [],
        }

    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings: List[str] = []

    # ------------------------------------------------------------------
    # 1. Parse the "Key Findings / Key Findings Summary" section
    #    This is the most reliable source of the counts.
    #    We support:
    #      - "### Key Findings Summary:"
    #      - "Key Findings Summary:"
    #      - bullets with or without bold, e.g.
    #          - **Critical Vulnerabilities:** 0
    #          - Critical Vulnerabilities: 0
    #      - list bullets "-", "*", "•"
    # ------------------------------------------------------------------
    summary_pattern = (
        r"(?:^|\n)#{0,3}\s*Key Findings(?: Summary)?\s*:?(.*?)(?:\n#{1,6}\s|\Z)"
    )
    summary_match = re.search(summary_pattern, report_md, re.DOTALL | re.IGNORECASE)

    if summary_match:
        summary_text = summary_match.group(1)

        # Primary patterns (compatible with old bolded markdown + tables)
        primary_patterns = {
            "critical": r"(?:-|\*|•|\|)\s*\*{0,2}Critical(?: Vulnerabilities)?\s*:?\*{0,2}\s*(?::|\|)?\s*(\d+)",
            "high": r"(?:-|\*|•|\|)\s*\*{0,2}High(?: Severity(?: Issues| Vulnerabilities)?)?\s*:?\*{0,2}\s*(?::|\|)?\s*(\d+)",
            "medium": r"(?:-|\*|•|\|)\s*\*{0,2}Medium(?: Severity(?: Issues| Vulnerabilities)?)?\s*:?\*{0,2}\s*(?::|\|)?\s*(\d+)",
            "low": r"(?:-|\*|•|\|)\s*\*{0,2}Low(?: Severity(?: Issues| Vulnerabilities)?)?\s*:?\*{0,2}\s*(?::|\|)?\s*(\d+)",
            "info": r"(?:-|\*|•|\|)\s*\*{0,2}Informational(?: Issues)?\s*:?\*{0,2}\s*(?::|\|)?\s*(\d+)",
        }

        for severity, pattern in primary_patterns.items():
            match = re.search(pattern, summary_text, re.IGNORECASE)
            if match:
                severities[severity] = int(match.group(1))

        # Fallback: simple "Label: N" lines (no bullets, no bold)
        if sum(severities.values()) == 0:
            fallback_patterns = {
                "critical": r"Critical Vulnerabilities:\s*(\d+)",
                "high": r"High Severity Vulnerabilities:\s*(\d+)",
                "medium": r"Medium Severity Vulnerabilities:\s*(\d+)",
                "low": r"Low Severity Vulnerabilities:\s*(\d+)",
                "info": r"Informational Issues:\s*(\d+)",
            }
            for severity, pattern in fallback_patterns.items():
                match = re.search(pattern, summary_text, re.IGNORECASE)
                if match:
                    severities[severity] = int(match.group(1))

    # ------------------------------------------------------------------
    # 2. Extract specific findings (titles) from headings
    # ------------------------------------------------------------------

    # Pattern A: "### Finding X: Title" or "### 4.1 Finding X: Title"
    pattern_a = r"###\s+(?:\d+\.\d+\s+)?Finding\s+\d+\s*:\s*(.+?)(?:\n|$)"
    matches_a = re.findall(pattern_a, report_md, re.IGNORECASE)

    finding_headers: List[str] = []
    for title in matches_a:
        finding_headers.append(title.strip())

    # Pattern B: "### X.X SEVERITY: Title"
    pattern_b = (
        r"###\s+(?:\d+\.\d+\s+)?(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*:\s*(.+?)(?:\n|$)"
    )
    matches_b = re.findall(pattern_b, report_md, re.IGNORECASE)
    for severity, title in matches_b:
        finding_headers.append(f"[{severity.upper()}] {title.strip()}")

    # Deduplicate and clean up
    seen = set()
    for f in finding_headers:
        if f not in seen:
            findings.append(f)
            seen.add(f)

    # If still no findings, use a loose heading-based heuristic
    if not findings:
        loose_pattern = r"####?\s+(.+?)(?:\n|$)"
        potential_loose = re.findall(loose_pattern, report_md)
        ignore_terms = [
            "summary",
            "methodology",
            "specification",
            "recommendation",
            "conclusion",
            "table of contents",
            "risk matrix",
            "description",
            "impact",
            "evidence",
            "steps to reproduce",
            "affected endpoints",
            "related cwe",
            "missing headers",
            "test execution",
            "compliance",
            "appendix",
            "additional endpoints",
            "response codes",
        ]
        for finding in potential_loose:
            if not any(x in finding.lower() for x in ignore_terms):
                findings.append(finding.strip())

    total = sum(severities.values())

    return {
        "severities": severities,
        "total": total,
        "findings": findings[:10],  # Top 10 findings
    }


def calculate_risk_score(severities: Dict[str, int]) -> int:
    """Calculate overall risk score based on vulnerability severities.

    Args:
        severities: Dictionary with counts per severity level

    Returns:
        Risk score from 0-100
    """
    weights = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 1,
    }

    score = sum(
        count * weights.get(sev.lower(), 0) for sev, count in severities.items()
    )

    # Cap at 100
    return min(score, 100)


def create_severity_chart(severities: Dict[str, int]) -> go.Figure:
    """Create a pie chart showing vulnerability distribution by severity.

    Args:
        severities: Dictionary with counts per severity level

    Returns:
        Plotly figure object
    """
    # Filter out zero counts
    filtered_sev = {k: v for k, v in severities.items() if v > 0}

    if not filtered_sev:
        # No vulnerabilities found - show placeholder
        fig = go.Figure(
            data=[
                go.Pie(
                    labels=["No Vulnerabilities"],
                    values=[1],
                    marker=dict(colors=["#28a745"]),
                    hole=0.4,
                )
            ]
        )
        fig.update_layout(
            title="Vulnerability Distribution",
            annotations=[
                dict(
                    text="All Clear!",
                    x=0.5,
                    y=0.5,
                    font_size=20,
                    showarrow=False,
                )
            ],
        )
        return fig

    # Define colors for each severity
    colors = {
        "critical": "#dc3545",  # Red
        "high": "#fd7e14",  # Orange
        "medium": "#ffc107",  # Yellow
        "low": "#17a2b8",  # Blue
        "info": "#6c757d",  # Gray
    }

    labels = [k.capitalize() for k in filtered_sev.keys()]
    values = list(filtered_sev.values())
    pie_colors = [colors.get(k, "#6c757d") for k in filtered_sev.keys()]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                marker=dict(colors=pie_colors),
                hole=0.4,
                textinfo="label+value",
                textfont_size=14,
            )
        ]
    )

    fig.update_layout(
        title={
            "text": "Vulnerability Distribution by Severity",
            "x": 0.5,
            "xanchor": "center",
        },
        height=400,
        showlegend=True,
        legend=dict(
            orientation="v",
            yanchor="middle",
            y=0.5,
            xanchor="left",
            x=1.02,
        ),
    )

    return fig


def create_risk_gauge(risk_score: int) -> go.Figure:
    """Create a gauge chart showing the risk score.

    Args:
        risk_score: Risk score from 0-100

    Returns:
        Plotly figure object
    """
    # Determine color based on risk level
    if risk_score < 20:
        color = "#28a745"  # Green
        level = "Low"
    elif risk_score < 40:
        color = "#17a2b8"  # Blue
        level = "Moderate"
    elif risk_score < 60:
        color = "#ffc107"  # Yellow
        level = "Elevated"
    elif risk_score < 80:
        color = "#fd7e14"  # Orange
        level = "High"
    else:
        color = "#dc3545"  # Red
        level = "Critical"

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number+delta",
            value=risk_score,
            title={"text": f"Risk Score: {level}"},
            delta={"reference": 50},
            gauge={
                "axis": {"range": [None, 100]},
                "bar": {"color": color},
                "steps": [
                    {"range": [0, 20], "color": "rgba(40, 167, 69, 0.2)"},
                    {"range": [20, 40], "color": "rgba(23, 162, 184, 0.2)"},
                    {"range": [40, 60], "color": "rgba(255, 193, 7, 0.2)"},
                    {"range": [60, 80], "color": "rgba(253, 126, 20, 0.2)"},
                    {"range": [80, 100], "color": "rgba(220, 53, 69, 0.2)"},
                ],
                "threshold": {
                    "line": {"color": "red", "width": 4},
                    "thickness": 0.75,
                    "value": 80,
                },
            },
        )
    )

    fig.update_layout(height=300)

    return fig
