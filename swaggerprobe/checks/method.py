from ..models import Finding
from ..request import build_request, send

ALL = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
DESTRUCTIVE = {"POST", "PUT", "PATCH", "DELETE"}
# OPTIONS/HEAD returning 2xx is normal (CORS preflight, HEAD mirroring GET) —
# not an "undeclared method" vulnerability, so never flag them.
SAFE_EXPECTED = {"OPTIONS", "HEAD"}


def run(op, ctx, baseline):
    findings = []
    declared = ctx.path_methods.get(op.path, set())
    for method in sorted(ALL - declared):
        if method in SAFE_EXPECTED:
            continue
        if method in DESTRUCTIVE and not ctx.allow_write:
            continue
        req, meta = build_request(op, ctx.base_url, ctx.auth, method=method)
        resp = send(req, timeout=ctx.timeout)
        ctx.requests_sent += 1
        if 200 <= resp.status < 300:
            sev = "HIGH" if method in DESTRUCTIVE else "MEDIUM"
            findings.append(Finding(sev, "method", method, op.path, meta, resp.status,
                                    f"undeclared {method} returned HTTP {resp.status}", "HIGH"))
    return findings
