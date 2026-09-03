from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


SENSITIVE_WORDS = {
    "password", "passwd", "pwd", "secret", "token", "credential",
    "apikey", "auth", "privatekey", "accesskey",
}
TEST_PATH_WORDS = {
    "test", "tests", "testing", "demo", "demo_project", "example", "examples", "sample",
    "samples", "fixture", "fixtures", "mock", "mocks",
}
THIRD_PARTY_PATH_WORDS = {
    "site-packages", "_internal", "vendor", "third_party", "node_modules",
    "sbom", "sboms", "dist-info",
}
DETECTOR_FEATURE_FILES = {"rules.py", "masking.py", "validation.py", "context.py"}
PLACEHOLDER_WORDS = {
    "test", "demo", "example", "dummy", "placeholder", "sample", "changeme",
    "yourapikey", "yourtoken", "yourpassword", "abcdef", "abc123", "password",
    "secret", "token",
}
SAFE_SOURCE_MARKERS = (
    "os.getenv", "os.environ", "process.env", "system.getenv", "std::env::var",
    "sys.getenv", "config.get", "load_secret", "load_runtime", "keyring.",
)


@dataclass(frozen=True, slots=True)
class ContextEvidence:
    variable_name: str | None
    is_sensitive_variable: bool
    is_hardcoded: bool
    is_safe_source: bool
    is_comment: bool
    is_test_path: bool
    is_third_party_source: bool
    is_detector_rule_feature: bool
    has_complete_private_key: bool
    is_placeholder: bool
    has_demo_marker: bool


def normalize_identifier(identifier: str) -> tuple[str, ...]:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", identifier)
    return tuple(part for part in re.split(r"[^A-Za-z0-9]+", separated.lower()) if part)


def is_placeholder_value(value: str) -> bool:
    stripped = value.strip().lower()
    compact = re.sub(r"[^a-z0-9]+", "", stripped)
    if compact in PLACEHOLDER_WORDS:
        return True
    if any(compact.startswith(word) for word in ("demo", "example", "dummy", "sample", "your")):
        return True
    if len(compact) >= 4 and len(set(compact)) == 1:
        return True
    return bool(re.fullmatch(r"(?:x+|0+|123456|654321)", compact))


def analyze_context(
    lines: list[str],
    line_index: int,
    value_span: tuple[int, int],
    value: str,
    relative_path: Path,
    source_path: Path | None = None,
) -> ContextEvidence:
    line = lines[line_index]
    prefix = line[:value_span[0]]
    suffix = line[value_span[1]:]
    variable_name = _extract_variable(prefix)
    tokens = normalize_identifier(variable_name or "")
    compact_name = "".join(tokens)
    is_sensitive = bool(set(tokens) & SENSITIVE_WORDS or compact_name in SENSITIVE_WORDS)

    lower_line = line.lower()
    safe_source = any(marker in lower_line for marker in SAFE_SOURCE_MARKERS)
    safe_source = safe_source or bool(re.search(r"\$\{[A-Za-z_][A-Za-z0-9_]*}", value))
    quoted_literal = prefix.rstrip().endswith(("\"", "'")) and suffix.lstrip().startswith(("\"", "'"))

    window = "\n".join(lines[max(0, line_index - 2):line_index + 3]).lower()
    has_complete_private_key = _has_complete_private_key(lines, line_index, value)
    return ContextEvidence(
        variable_name=variable_name,
        is_sensitive_variable=is_sensitive,
        is_hardcoded=quoted_literal and not safe_source,
        is_safe_source=safe_source,
        is_comment=_is_comment(prefix, line),
        is_test_path=_is_test_path(relative_path) or bool(source_path and _is_test_path(source_path)),
        is_third_party_source=(
            _is_third_party_path(relative_path)
            or bool(source_path and _is_third_party_path(source_path))
        ),
        is_detector_rule_feature=_is_detector_rule_feature(
            source_path or relative_path,
            line,
            value,
            has_complete_private_key,
        ),
        has_complete_private_key=has_complete_private_key,
        is_placeholder=is_placeholder_value(value),
        has_demo_marker="demo only" in window or "invalid test credential" in window,
    )


def _extract_variable(prefix: str) -> str | None:
    match = re.search(
        r"[\"']?([A-Za-z_][A-Za-z0-9_-]*)[\"']?"
        r"(?:\s*:\s*[^=:\"']{1,40})?\s*(?:=|:|<-)\s*[\"']?\s*$",
        prefix,
    )
    return match.group(1) if match else None


def _is_comment(prefix: str, line: str) -> bool:
    stripped = line.lstrip()
    if stripped.startswith(("#", "//", "/*", "*", "<!--")):
        return True
    return any(marker in prefix for marker in ("//", "<!--")) or "#" in prefix


def _is_test_path(path: Path) -> bool:
    return bool(_path_labels(path) & TEST_PATH_WORDS)


def _is_third_party_path(path: Path) -> bool:
    labels = _path_labels(path)
    return bool(labels & THIRD_PARTY_PATH_WORDS) or any(
        part.casefold().endswith(".dist-info") for part in path.parts
    )


def _path_labels(path: Path) -> set[str]:
    labels: set[str] = set()
    for part in path.parts:
        lowered = part.casefold()
        labels.add(lowered)
        labels.update(value for value in re.split(r"[^a-z0-9]+", lowered) if value)
    return labels


def _has_complete_private_key(lines: list[str], line_index: int, value: str) -> bool:
    if not value.startswith("-----BEGIN "):
        return False
    # 延迟导入避免 context 与 validation 的模块初始化彼此耦合。
    from codeshield.validation import validate_private_key_structure

    return validate_private_key_structure(lines, line_index, value)


def _is_detector_rule_feature(
    path: Path,
    line: str,
    value: str,
    has_complete_private_key: bool,
) -> bool:
    parts = tuple(part.casefold() for part in path.parts)
    if path.name.casefold() not in DETECTOR_FEATURE_FILES or "codeshield" not in parts:
        return False
    if has_complete_private_key:
        return False
    if value.startswith("-----BEGIN "):
        return True
    lowered = line.casefold()
    return path.name.casefold() in {"validation.py", "context.py"} and "password=" in lowered and ".split(" in lowered
