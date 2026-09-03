from __future__ import annotations

from dataclasses import dataclass

from codeshield.config import AppConfig
from codeshield.context import ContextEvidence
from codeshield.entropy import calculate_entropy
from codeshield.models import RiskFactor, Rule
from codeshield.validation import database_credential_kind, validate_jwt_structure


CREDENTIAL_TYPES = {"Password", "API Key", "Secret", "Token", "JWT", "Database Credential"}


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: int
    severity: str
    entropy: float
    factors: tuple[RiskFactor, ...]


def severity_for_score(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def assess_risk(rule: Rule, value: str, context: ContextEvidence, config: AppConfig) -> RiskAssessment:
    factors = [RiskFactor("rule", rule.score, f"命中规则：{rule.name}")]
    entropy = calculate_entropy(value)

    if context.is_sensitive_variable:
        factors.append(RiskFactor("sensitive_context", 12, f"敏感变量：{context.variable_name}"))
    if context.is_hardcoded:
        factors.append(RiskFactor("hardcoded_literal", 12, "直接字符串赋值"))

    # 熵只增强已经命中规则的候选，并且要求足够长度，不能单独制造高风险 Finding。
    if (
        rule.risk_type in CREDENTIAL_TYPES
        and len(value) >= config.min_entropy_length
        and entropy >= config.entropy_threshold
    ):
        factors.append(RiskFactor("high_entropy", 8, f"信息熵：{entropy:.2f}"))
    if rule.risk_type in CREDENTIAL_TYPES and len(value) >= 16:
        factors.append(RiskFactor("credential_length", 4, f"字符串长度：{len(value)}"))

    if rule.risk_type == "Private Key":
        if context.has_complete_private_key:
            factors.append(RiskFactor("complete_pem", 15, "完整 PEM 结构"))
            factors.append(RiskFactor("private_key_body", 10, "私钥正文结构特征"))
        else:
            factors.append(RiskFactor("private_key_header_only", -55, "仅发现私钥起始标记，缺少完整 PEM 结构"))

    format_bonus = _format_bonus(rule.risk_type, value)
    if format_bonus:
        factors.append(RiskFactor("credential_format", format_bonus, "凭证格式证据较强"))

    # 注释、测试目录和占位值仍可能包含真凭证，因此只降权而不删除结果。
    if context.is_comment:
        factors.append(RiskFactor("comment", -12, "位于注释中"))
    if context.is_test_path:
        factors.append(RiskFactor("test_path", -10, "测试或演示数据：风险降低"))
    if context.is_third_party_source:
        factors.append(RiskFactor("third_party_source", -15, "第三方依赖/元数据：风险降低"))
        if rule.risk_type == "Email":
            factors.append(RiskFactor("public_contact", -8, "公开联系方式特征"))
    if context.is_detector_rule_feature:
        factors.append(RiskFactor("detector_rule_feature", -40, "检测器内部规则特征：风险降低"))
    if context.has_demo_marker:
        factors.append(RiskFactor("demo_marker", -8, "附近标记为无效演示数据"))
    if context.is_placeholder:
        factors.append(RiskFactor("placeholder", -18, "疑似测试或占位值"))
    if context.is_safe_source:
        factors.append(RiskFactor("safe_source", -45, "值来自环境变量或动态来源"))

    score = max(0, min(100, sum(factor.points for factor in factors)))
    return RiskAssessment(score, severity_for_score(score), entropy, tuple(factors))


def _format_bonus(risk_type: str, value: str) -> int:
    if risk_type == "JWT" and validate_jwt_structure(value):
        return 10
    if risk_type == "Database Credential" and database_credential_kind(value) == "plaintext":
        return 10
    if risk_type == "ID Card":
        return 8
    return 0
