import re
import time

from ..models import Finding
from ..request import build_request, send

PAYLOADS = ["'", "{{7*7}}", "../../../../etc/passwd", "$(id)"]
ERROR_RE = re.compile(r"(sql syntax|sqlite|mysql|postgres|ora-|odbc|traceback|root:x:0:0|uid=\d+|syntax error)", re.I)


def run(op, ctx, baseline):
    findings = []
    base_resp = baseline["response"]
    for param in [p for p in op.params if p.location in {"path", "query", "header"}]:
        for payload in PAYLOADS:
            req, meta = build_request(op, ctx.base_url, ctx.auth, overrides={param.name: payload})
            resp = send(req, timeout=ctx.timeout)
            ctx.requests_sent += 1
            evidence = _evidence(resp.body)
            if evidence and evidence not in base_resp.body:
                findings.append(Finding(_severity(evidence), "injection", op.method, op.path, meta, resp.status,
                                        f"{param.name} triggered {evidence}", "HIGH"))
            elif resp.status >= 500 and base_resp.status < 500:
                findings.append(Finding("MEDIUM", "injection", op.method, op.path, meta, resp.status,
                                        f"{param.name} caused HTTP {resp.status} vs baseline {base_resp.status}", "MEDIUM"))
            elif payload == "{{7*7}}" and "49" in resp.body and "49" not in base_resp.body:
                findings.append(Finding("HIGH", "injection", op.method, op.path, meta, resp.status,
                                        f"{param.name} reflected SSTI math result 49", "HIGH"))
        if ctx.time_based:
            req, meta = build_request(op, ctx.base_url, ctx.auth, overrides={param.name: "sleep(2)"})
            first = send(req, timeout=max(ctx.timeout, 5))
            second = send(req, timeout=max(ctx.timeout, 5))
            ctx.requests_sent += 2
            if first.elapsed > base_resp.elapsed + 1.5 and second.elapsed > base_resp.elapsed + 1.5:
                findings.append(Finding("LOW", "injection", op.method, op.path, meta, second.status,
                                        f"{param.name} repeated time delay", "LOW"))
                time.sleep(0)
    return findings


def _evidence(body):
    match = ERROR_RE.search(body or "")
    return match.group(1) if match else ""


def _severity(evidence):
    ev = evidence.lower()
    if "root:x:0:0" in ev:
        return "HIGH"
    if "sql" in ev or "sqlite" in ev or "mysql" in ev:
        return "HIGH"
    return "MEDIUM"
