"""Secret masking. Raw secret-bearing content is never stored or logged."""
from __future__ import annotations

import base64
import binascii
import re

MASK = "***MASKED***"

_ASSIGN = r"""["']?\s*(?:=|:\s|:(?=["']))\s*["']?"""

# (type, pattern). Only the *type* and location of a hit are reported, never the match.
_PATTERNS = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_secret_access_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S{20,}")),
    # \w* on both sides so env-style names such as DB_PASSWORD= or client_secret: are caught. The separator must look
    # like an assignment ("=", ": " or a JSON "key": value), so IAM actions and ARNs such as
    # "secretsmanager:GetSecretValue" or "arn:aws:secretsmanager:...:secret:name" are not mistaken for secrets.
    ("password_assignment", re.compile(r"(?i)\w*(?:password|passwd|pwd)\w*" + _ASSIGN + r"\S+")),
    ("secret_assignment", re.compile(r"(?i)\w*(?:secret|token|api[_-]?key)\w*" + _ASSIGN + r"\S+")),
    ("basic_auth_url", re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@")),
]


def scan_text(text: str) -> list[dict]:
    """Return ``[{"type", "line"}]`` for every secret-looking line."""
    found = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for kind, pat in _PATTERNS:
            if pat.search(line):
                found.append({"type": kind, "line": lineno})
    return found


def mask_user_data(value: str | None, scan: bool, location: str) -> tuple[str | None, list[dict]]:
    """Mask a (usually base64) UserData value. With ``scan`` the decoded text is checked for secrets."""
    if value is None or value == "":
        return value, []
    findings: list[dict] = []
    if scan:
        try:
            text = base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            text = value
        findings = [{"location": location, **f} for f in scan_text(text)]
    return MASK, findings


def mask_environment(variables: dict | None, location: str) -> tuple[dict | None, list[dict]]:
    """Mask every value of an environment-variable map (Lambda, ECS, CodeBuild)."""
    if not variables:
        return variables, []
    findings = []
    masked = {}
    for name, value in variables.items():
        masked[name] = MASK
        hits = scan_text(f"{name}={value}")
        findings += [{"location": f"{location}.{name}", "type": h["type"]} for h in hits]
    return masked, findings
