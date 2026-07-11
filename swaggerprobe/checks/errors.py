import re

from ..models import Finding

LEAK_RE = re.compile(
    r"(Traceback \(most recent call last\)|at [\w.$]+\(.*:\d+\)|debug\s*=\s*true|"
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b|"
    r"(?:Apache|nginx|Express|Django|Flask|Werkzeug)/\d|SELECT [^\n]{1,200}? FROM|SQLSTATE)",
    re.I | re.S,
)


def run(op, ctx, baseline):
    resp = baseline["response"]
    match = LEAK_RE.search(resp.body or "")
    if not match:
        return []
    sev = "MEDIUM" if resp.status >= 500 or "traceback" in match.group(1).lower() else "LOW"
    return [Finding(sev, "errors", op.method, op.path, baseline["request"], resp.status,
                    f"verbose leak: {match.group(1)[:60]}", "HIGH")]
