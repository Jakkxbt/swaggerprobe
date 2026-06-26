from ..models import Finding
from ..request import build_request, send


def run(op, ctx, baseline):
    if op.security == [] or not op.security:
        return []
    findings = []
    for label, headers in (("missing credentials", {}), ("bogus token", {"Authorization": "Bearer swaggerprobe-bogus"})):
        req, meta = build_request(op, ctx.base_url, headers)
        resp = send(req, timeout=ctx.timeout)
        ctx.requests_sent += 1
        if 200 <= resp.status < 400:
            sev = "CRITICAL" if _looks_like_data(resp.body) else "HIGH"
            findings.append(Finding(sev, "auth", op.method, op.path, meta, resp.status,
                                    f"{label} returned HTTP {resp.status}", "HIGH"))
    return findings


def _looks_like_data(body):
    body = (body or "").strip()
    return body.startswith(("{", "[")) and len(body) > 2
