from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from codeshield.config import AppConfig
from codeshield.context import analyze_context
from codeshield.masking import mask_value
from codeshield.models import Finding, Rule
from codeshield.risk import assess_risk
from codeshield.validation import database_credential_kind, validate_china_id, validate_jwt_structure


logger = logging.getLogger(__name__)

PERSONAL_INFO_TYPES = {"Email", "Phone", "ID Card"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(slots=True)
class RuleLoadResult:
    rules: list[Rule]
    errors: list[str]


def builtin_rules_path() -> Path:
    return Path(__file__).resolve().parent.parent / "rules" / "builtin_rules.json"


def load_rules(path: Path | None = None) -> RuleLoadResult:
    rule_path = path or builtin_rules_path()
    try:
        payload = json.loads(rule_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return RuleLoadResult([], [f"无法读取规则文件：{type(exc).__name__}"])

    if not isinstance(payload, list):
        return RuleLoadResult([], ["规则文件顶层必须是数组"])

    rules: list[Rule] = []
    errors: list[str] = []
    for index, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            errors.append(f"第 {index} 条规则不是对象")
            continue
        if not item.get("enabled", True):
            continue
        try:
            rule = _build_rule(item)
        except (KeyError, TypeError, ValueError, re.error) as exc:
            rule_id = item.get("id", f"#{index}")
            errors.append(f"规则 {rule_id} 已禁用：{type(exc).__name__}")
            logger.warning("规则 %s 无法加载：%s", rule_id, type(exc).__name__)
            continue
        rules.append(rule)
    return RuleLoadResult(rules, errors)


def _build_rule(item: dict[str, object]) -> Rule:
    rule_id = str(item["id"])
    name = str(item["name"])
    risk_type = str(item["risk_type"])
    severity = str(item["severity"]).lower()
    score = int(item["score"])
    languages = item["languages"]
    description = str(item["description"])
    suggestion = str(item["suggestion"])

    if severity not in SEVERITY_ORDER or not 0 <= score <= 100:
        raise ValueError("invalid severity or score")
    if not isinstance(languages, list) or not all(isinstance(value, str) for value in languages):
        raise TypeError("languages must be a string array")

    # 命名组让检测器只脱敏真正的凭证部分，避免把变量名和整行代码一起隐藏。
    pattern = re.compile(str(item["pattern"]))
    if "value" not in pattern.groupindex:
        raise ValueError("pattern requires a value group")

    return Rule(
        rule_id,
        name,
        risk_type,
        pattern,
        severity,
        score,
        frozenset(languages),
        description,
        suggestion,
    )


class RuleDetector:
    def __init__(self, rules: list[Rule], config: AppConfig) -> None:
        self.config = config
        self.rules = [
            rule
            for rule in rules
            if config.detect_personal_info or rule.risk_type not in PERSONAL_INFO_TYPES
        ]

    def detect(self, text: str, file_path: Path, relative_path: Path, language: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()
        for line_index, line in enumerate(lines):
            line_number = line_index + 1
            line_matches: dict[tuple[int, int], tuple[Rule, re.Match[str]]] = {}
            for rule in self.rules:
                if language not in rule.languages:
                    continue
                for match in rule.pattern.finditer(line):
                    span = match.span("value")
                    previous = line_matches.get(span)
                    if previous is None or rule.score > previous[0].score:
                        # 明确格式规则与通用赋值规则重叠时，只保留证据更强的一条结果。
                        line_matches[span] = (rule, match)

            for rule, match in line_matches.values():
                value = match.group("value")
                if not _valid_candidate(rule.risk_type, value):
                    continue
                evidence = analyze_context(lines, line_index, match.span("value"), value, relative_path)
                assessment = assess_risk(rule, value, evidence, self.config)
                masked = mask_value(value, rule.risk_type)
                fingerprint = hashlib.sha256(
                    f"{rule.id}\0{relative_path.as_posix()}\0{line_number}\0{value}".encode("utf-8")
                ).hexdigest()
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        risk_type=rule.risk_type,
                        severity=assessment.severity,
                        score=assessment.score,
                        file_path=str(file_path),
                        relative_path=str(relative_path),
                        line_number=line_number,
                        column=match.start("value") + 1,
                        language=language,
                        masked_value=masked,
                        reason=rule.description,
                        suggestion=rule.suggestion,
                        rule_name=rule.name,
                        entropy=assessment.entropy,
                        risk_factors=assessment.factors,
                        is_placeholder=evidence.is_placeholder,
                        is_comment=evidence.is_comment,
                        is_hardcoded=evidence.is_hardcoded,
                        context=_safe_context(line_number, rule.name, evidence.variable_name, masked),
                        fingerprint=fingerprint,
                    )
                )
        return findings


def _valid_candidate(risk_type: str, value: str) -> bool:
    if risk_type == "ID Card":
        return validate_china_id(value)
    if risk_type == "JWT":
        return validate_jwt_structure(value)
    if risk_type == "Database Credential":
        return database_credential_kind(value) != "none"
    return True


def _safe_context(line_number: int, rule_name: str, variable_name: str | None, masked: str) -> str:
    # 上下文只保存重建后的脱敏摘要，避免同一源码行中的其他凭证被顺带写入 Finding。
    label = variable_name or rule_name
    return f"{line_number}: {label} = {masked}"


def finding_sort_key(finding: Finding) -> tuple[int, str, int, int, str]:
    return (
        SEVERITY_ORDER.get(finding.severity, 99),
        finding.relative_path.casefold(),
        finding.line_number,
        finding.column,
        finding.rule_id,
    )
