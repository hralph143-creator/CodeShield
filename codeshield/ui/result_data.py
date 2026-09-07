from __future__ import annotations

from collections.abc import Iterable

from codeshield.models import Finding
from codeshield.ui.styles import CRITICAL, HIGH, LOW, MEDIUM, MUTED, PRIMARY, SUCCESS


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
    "critical": ("#FDECEC", "#C9363E", CRITICAL),
    "high": ("#FFF4DE", "#B76400", HIGH),
    "medium": ("#FFF9D9", "#8A6800", MEDIUM),
    "low": ("#EAF2FF", "#245FB8", LOW),
}
STATUS_COLORS = {
    "unresolved": MUTED,
    "unhandled": MUTED,
    "confirmed": PRIMARY,
    "false_positive": "#B54708",
    "ignored": "#7A5AF8",
    "fixed": SUCCESS,
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


def source_label(finding: Finding) -> str:
    keys = {factor.key for factor in finding.risk_factors}
    if "detector_rule_feature" in keys:
        return "检测器内部规则特征"
    if "third_party_source" in keys:
        return "第三方依赖/元数据"
    if "test_path" in keys:
        return "测试/演示数据"
    if "generated_source" in keys:
        return "生成或发布产物"
    return "项目源码"


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
        "source": source_label(finding),
        "masked_value": finding.masked_value,
        "entropy": f"{finding.entropy:.2f}" if finding.entropy > 0 else "—",
        "factors": factor_lines(finding),
        "context": finding.context,
        "suggestion": finding.suggestion,
    }
