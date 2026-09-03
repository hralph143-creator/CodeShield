from __future__ import annotations

import base64
import json
import re
from datetime import datetime


ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
ID_CHECK_CODES = "10X98765432"
BASE64URL_PART = re.compile(r"^[A-Za-z0-9_-]+$")
PRIVATE_KEY_HEADER = re.compile(r"^-----BEGIN ((?:RSA |EC |OPENSSH )?PRIVATE KEY)-----$")
PEM_BODY_LINE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def validate_china_id(value: str) -> bool:
    normalized = value.upper()
    if not re.fullmatch(r"[1-9]\d{16}[0-9X]", normalized):
        return False
    try:
        birthday = datetime.strptime(normalized[6:14], "%Y%m%d").date()
    except ValueError:
        return False
    if not 1800 <= birthday.year <= datetime.now().year:
        return False

    # 校验位由前 17 位与固定权重计算，测试数据仍使用不存在的地区码避免指向真人。
    checksum = sum(int(digit) * weight for digit, weight in zip(normalized[:17], ID_WEIGHTS))
    return normalized[-1] == ID_CHECK_CODES[checksum % 11]


def validate_jwt_structure(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 3 or not all(parts) or not all(BASE64URL_PART.fullmatch(part) for part in parts):
        return False
    try:
        header = _decode_json_part(parts[0])
        payload = _decode_json_part(parts[1])
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return False
    return isinstance(header, dict) and isinstance(payload, dict) and bool(header)


def database_credential_kind(value: str) -> str:
    lowered = value.lower()
    if re.search(r"\$\{[a-z_][a-z0-9_]*}", lowered):
        return "dynamic"
    if re.search(r"://[^\s:/@]+:[^\s/@]+@", value):
        return "plaintext"
    if lowered.startswith("jdbc:") and "password=" in lowered:
        password = lowered.split("password=", 1)[1].split("&", 1)[0]
        return "dynamic" if "${" in password else "plaintext"
    return "none"


def validate_private_key_structure(lines: list[str], header_index: int, header: str) -> bool:
    """只验证 PEM 的结构特征，不拼接或返回私钥正文。"""
    match = PRIVATE_KEY_HEADER.fullmatch(header.strip())
    if not match or not 0 <= header_index < len(lines):
        return False

    expected_end = f"-----END {match.group(1)}-----"
    body_length = 0
    body_lines = 0
    for line in lines[header_index + 1:header_index + 202]:
        stripped = line.strip()
        if stripped == expected_end:
            return body_lines > 0 and body_length >= 64
        if not stripped:
            continue
        if stripped.startswith("-----BEGIN ") or not PEM_BODY_LINE.fullmatch(stripped):
            return False
        body_lines += 1
        body_length += len(stripped.rstrip("="))
    return False


def _decode_json_part(value: str) -> object:
    padding = "=" * (-len(value) % 4)
    decoded = base64.urlsafe_b64decode(value + padding)
    return json.loads(decoded.decode("utf-8"))
