from __future__ import annotations

from collections.abc import Iterable

from codeshield.models import Finding


SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
}
STATUS_LABELS = {
    "unresolved": "未处理",
    "unhandled": "未处理",
    "confirmed": "已确认",
    "false_positive": "误报",
    "ignored": "已忽略",
    "fixed": "已修复",
}
RISK_TYPE_LABELS = {
    "Password": "密码",
    "API Key": "API Key",
    "Secret": "敏感密钥",
    "Token": "Token",
    "JWT": "JWT",
    "Private Key": "Private Key",
    "Database Credential": "数据库凭证",
    "Email": "邮箱",
    "Phone": "手机号",
    "ID Card": "身份证",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLORS = {
    "critical": ("#FDECEC", "#C9363E", "#E5484D"),
    "high": ("#FFF4DE", "#B76400", "#F59E0B"),
    "medium": ("#FFF9D9", "#8A6800", "#EAB308"),
    "low": ("#EAF2FF", "#245FB8", "#3B82F6"),
}
STATUS_COLORS = {
    "unresolved": "#667085",
    "unhandled": "#667085",
    "confirmed": "#175CD3",
    "false_positive": "#B54708",
    "ignored": "#7A5AF8",
    "fixed": "#067647",
}


def filter_findings(
    findings: Iterable[Finding],
    keyword: str = "",
    severity: str = "",
    risk_type: str = "",
    language: str = "",
) -> list[Finding]:
    term = keyword.strip().casefold()
    filtered = []
    for finding in findings:
        searchable = " ".join(
            (finding.relative_path, finding.risk_type, finding.rule_id, finding.rule_name)
        ).casefold()
        if term and term not in searchable:
            continue
        if severity and finding.severity != severity:
            continue
        if risk_type and finding.risk_type != risk_type:
            continue
        if language and finding.language != language:
            continue
        filtered.append(finding)
    return sorted(
        filtered,
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity, 99),
            -item.score,
            item.relative_path.casefold(),
            item.line_number,
            item.column,
        ),
    )


def factor_lines(finding: Finding) -> list[str]:
    return [f"{factor.points:+d}  {factor.detail}" for factor in finding.risk_factors]


def detail_data(finding: Finding) -> dict[str, str | list[str]]:
    return {
        "risk_type": RISK_TYPE_LABELS.get(finding.risk_type, finding.risk_type),
        "severity": SEVERITY_LABELS.get(finding.severity, finding.severity),
        "score": f"{finding.score} / 100",
        "rule": finding.rule_name or finding.rule_id,
        "language": finding.language,
        "file": finding.relative_path,
        "location": f"第 {finding.line_number} 行，第 {finding.column} 列",
        "status": STATUS_LABELS.get(finding.status, finding.status),
        "masked_value": finding.masked_value,
        "entropy": f"{finding.entropy:.2f}" if finding.entropy > 0 else "—",
        "factors": factor_lines(finding),
        "context": finding.context,
        "suggestion": finding.suggestion,
    }
