from __future__ import annotations

PRIVATE_KEY_HEADERS = {
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
}


def mask_value(value: str, risk_type: str) -> str:
    normalized_type = risk_type.lower()
    if normalized_type == "password":
        return "********"
    if normalized_type == "private key":
        header = next((item for item in PRIVATE_KEY_HEADERS if item in value), "PRIVATE KEY")
        return f"{header} [MASKED]"
    if normalized_type == "phone":
        return f"{value[:3]}****{value[-4:]}" if len(value) == 11 else "********"
    if normalized_type == "id card":
        return f"{value[:3]}{'*' * max(len(value) - 7, 4)}{value[-4:]}"
    if normalized_type == "email":
        local, separator, domain = value.partition("@")
        return f"{local[:1]}***{separator}{domain}" if separator else "********"
    if normalized_type == "database credential":
        scheme = value.split(":", 1)[0]
        return f"{scheme}://***:***@[MASKED]"

    # Token 类结果只保留少量首尾字符，足够区分记录但不能还原凭证。
    if len(value) <= 8:
        return "*" * len(value)
    visible = 4 if len(value) >= 16 else 2
    return f"{value[:visible]}{'*' * (len(value) - visible * 2)}{value[-visible:]}"
